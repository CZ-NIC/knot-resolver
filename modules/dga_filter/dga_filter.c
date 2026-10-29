/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
*  SPDX-License-Identifier: GPL-3.0-or-later
*/

/**
 * @file dga_filter.c
 * @brief blocks DGA domains using ML
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpsl.h>

#include "lib/layer.h"
#include "lib/resolve.h"

#include "model_features.h"

#define DGA_FAIL_PROB -1
#define DGA_BYPASS_MIN_SLD_LEN 4

struct {
	bool model_loaded;
	kr_rule_tags_t tags;
	uint16_t threshold;
} config = {0};

bool load_attempted = false;

/// Returns the probability of DGA in percent, or DGA_FAIL_PROB on error.
float get_model_inference(const char* name)
{
	if (!config.model_loaded) return DGA_FAIL_PROB;

	float prob_dga = dga_predict(name);
	if (prob_dga < 0.0f) return DGA_FAIL_PROB;
	return prob_dga * 100;
}

char *get_label_before_suffix(knot_dname_t *domain)
{
	char str_domain[256];
	const psl_ctx_t *psl;
	const char *regdom;
	size_t domain_len;
	char *copy;
	char *dot;

	if (!domain) return NULL;

	knot_dname_to_str(str_domain, domain, sizeof(str_domain));

	psl = psl_builtin();
	if (!psl) return NULL;

	regdom = psl_registrable_domain(psl, (char *)str_domain);
	if (!regdom) return NULL;

	domain_len = strnlen(regdom, 256);
	copy = malloc(domain_len + 1);
	if (!copy) return NULL;

	memcpy(copy, regdom, domain_len);
	copy[domain_len] = '\0';

	dot = strchr(copy, '.');
	if (dot) *dot = '\0';

	for (char *p = copy; *p; p++)
		*p = (char)tolower((unsigned char)*p);

	return copy;
}

void load_model(const char *model_path)
{
	if (dga_model_load(model_path) != 0) {
		kr_log_crit(DGA, "failed to load DGA model container '%s'\n", model_path);
		config.model_loaded = false;
		return;
	}
	kr_log_info(DGA, "loaded DGA model '%s'\n", model_path);
	config.model_loaded = true;
}

void free_model(void)
{
	if (!config.model_loaded) return;
	dga_model_unload();
	config.model_loaded = false;
}

KR_EXPORT
int dga_filter_setup(const char *model, kr_rule_tags_t tags, uint16_t threshold)
{
	config.tags = tags;
	config.threshold = threshold;

	int ret;
	load_model(model);
	if (!config.model_loaded) {
		ret = kr_error(EINVAL); // we don't know what's wrong
		goto fail;
	}

	return 0;
fail:
	free_model();
	kr_log_crit(DGA, "Initialization of shared DGA filter data failed.\n");
	load_attempted = true;
	return ret;
}

KR_EXPORT
int dga_filter_refresh_tags(kr_rule_tags_t tags)
{
	config.tags = tags;
	kr_log_debug(DGA, "Tags updated: filter=0x%lx\n",
			(unsigned long)tags);

	return kr_ok();
}

/// Ensure that the filter is loaded; return false if failed.
static bool ensure_loaded(void)
{
	if (config.model_loaded)
		return true;
	if (load_attempted)
		return false;

	kr_log_warning(DGA, "DGA filter not initialized from Lua, using hardcoded default.\n");
	int ret = dga_filter_setup("/home/dgad.dgamodel" , KR_RULE_TAGS_ALL, 31);// FIXME TMP
	return ret == kr_ok();
}

static void do_filter(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (!ensure_loaded())
		return;
	if (kr_request_unblocked(req))
		return;
	if (!req->qsource.addr)
		return;  // don't consider internal requests
	if (req->qsource.price_factor16 == 0)
		return;  // whitelisted
	if (qry->flags.CACHED) {
		return; // don't consider cached results
	}
	if (req->options.DGA_CHECKED) {
		return; // don't consider already checked requests
	}

	req->options.DGA_CHECKED = 1;

	// this logic comes from kr_rule_consume_tags()
	// Per-packet detection
	// _apply tags take precendence, and we store the last one
	kr_rule_tags_t const det_tags_apply = config.tags & req->rule_tags_apply;
	const bool det_do_apply = config.tags == KR_RULE_TAGS_ALL || det_tags_apply;
	// _audit: we fill everything if we're the very first action
	kr_rule_tags_t const det_tags_audit = config.tags & req->rule_tags_audit;
	const bool det_do_audit = det_tags_audit && !req->rule.action;

	if (!det_do_apply && !det_do_audit)
		return; // we save the expensive computations

	kr_rule_tags_t req_tags = det_do_apply ? det_tags_apply : det_tags_audit;

	float dga_prob = -1;

	char *label = get_label_before_suffix(qry->sname);
	if (label) {
		if (strlen(label) < DGA_BYPASS_MIN_SLD_LEN) {
			dga_prob = 0.0f;
		} else {
			dga_prob = get_model_inference(label);
		}
		free(label);
		label = NULL;
	}

	if (dga_prob <= config.threshold) {
		return;
	}

	kr_log_debug(DGA, "Malicious packet detected! (%f %%) %s\n",
			(dga_prob),
			(det_do_apply ? "Blocking." : "Auditing.")
	);

	if (det_do_apply) {
		req->rule.tags = req_tags; // .action is filled by _do_answer()
		kr_rule_do_answer(KR_RULE_SUB_NXDOMAIN, qry, pkt, qry->sname);
	} else {
		kr_assert(det_do_audit);
		req->rule.tags = req_tags;
		req->rule.action = KREQ_ACTION_AUDIT;
	}
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	do_filter(ctx, pkt);
	return ctx->state;
}

/// Unmap the model (the file pages stay in the page cache for other processes).
KR_EXPORT
int dga_filter_deinit(struct kr_module *self)
{
	free_model();
	return kr_ok();
}

KR_EXPORT
int dga_filter_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.produce = produce,
	};
	layer.data = module;
	module->layer = &layer;

	return kr_ok();
}

KR_MODULE_EXPORT(dga_filter)
