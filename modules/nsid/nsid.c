/* Copyright (C) Knot Resolver contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This module provides NSID support according to RFC 5001. */

#include <libknot/packet/pkt.h>
#include <contrib/cleanup.h>
#include <ccan/json/json.h>
#include <lauxlib.h>

#include "daemon/engine.h"
#include "lib/layer.h"

struct nsid_config {
	uint8_t *local_nsid;
	size_t local_nsid_len;
};

static int nsid_finalize(kr_layer_t *ctx) {
	const struct kr_module *module = ctx->api->data;
	const struct nsid_config *config = module->data;
	struct kr_request *req = ctx->req;

	/* no local NSID configured, do nothing */
	if (config->local_nsid == NULL)
		return ctx->state;

	const knot_rrset_t *src_opt = req->qsource.packet->opt_rr;
	/* no EDNS in request, do nothing */
	if (src_opt == NULL)
		return ctx->state;

	const uint8_t *req_nsid = knot_edns_get_option(src_opt, KNOT_EDNS_OPTION_NSID, NULL);
	/* NSID option must be explicitly requested */
	if (req_nsid == NULL)
		return ctx->state;

	/* Check violation of https://tools.ietf.org/html/rfc5001#section-2.1:
	 * The resolver MUST NOT include any NSID payload data in the query */
	if (knot_edns_opt_get_length(req_nsid) != 0)
		kr_log_debug(NSID, "[%05u.  ] FORMERR: NSID option in query "
			       "must not contain payload, continuing\n", req->uid);
		/* FIXME: actually change RCODE in answer to FORMERR? */

	/* Sanity check, answer should have EDNS as well but who knows ... */
	if (kr_fails_assert(req->answer->opt_rr))
		return ctx->state;

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_NSID,
				 config->local_nsid_len, config->local_nsid,
				 &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
		kr_log_debug(NSID, "[%05u.  ] unable to add NSID option\n", req->uid);
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
	}

	return ctx->state;
}

static char* nsid_name(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;
	struct nsid_config *config = module->data;
	if (args) {  /* set */
		/* API is not binary safe, we need to fix this one day */
		uint8_t *arg_copy = (uint8_t *)strdup(args);
		if (arg_copy == NULL)
			luaL_error(engine->L, "[nsid] error while allocating new NSID value\n");
		free(config->local_nsid);
		config->local_nsid = arg_copy;
		config->local_nsid_len = strlen(args);
	}

	/* get */
	if (config->local_nsid != NULL)
		return json_encode_string((char *)config->local_nsid);
	else
		return NULL;
}

KR_EXPORT
int nsid_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.answer_finalize = &nsid_finalize,
	};
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { &nsid_name, "name", "Get or set local NSID value" },
	    { NULL, NULL, NULL }
	};
	module->props = props;

	struct nsid_config *config = calloc(1, sizeof(struct nsid_config));
	if (config == NULL)
		return kr_error(ENOMEM);

	module->data = config;
	return kr_ok();
}

KR_EXPORT
int nsid_deinit(struct kr_module *module) {
	struct nsid_config *config = module->data;
	if (config != NULL) {
		free(config->local_nsid);
		free(config);
		module->data = NULL;
	}
	return kr_ok();
}

KR_MODULE_EXPORT(nsid)
