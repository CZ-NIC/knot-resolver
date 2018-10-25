/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
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

static int nsid_finish(kr_layer_t *ctx) {
	const struct kr_request *req = ctx->req;
	const knot_pkt_t* answer = req->answer;
	const struct kr_module *module = ctx->api->data;
	struct nsid_config *config = module->data;

	/* no local NSID configured, do nothing */
	if (config->local_nsid == NULL)
		return ctx->state;

	/* no EDNS in request, do nothing */
	if (req->qsource.opt == NULL)
		return ctx->state;

	const uint8_t *req_nsid = knot_edns_get_option(req->qsource.opt,
						       KNOT_EDNS_OPTION_NSID);
	/* NSID option must be explicitly requested */
	if (req_nsid == NULL)
		return ctx->state;

	/* Check violation of https://tools.ietf.org/html/rfc5001#section-2.1:
	 * The resolver MUST NOT include any NSID payload data in the query */
	if (knot_edns_opt_get_length(req_nsid) != 0)
		kr_log_verbose("[%05u][nsid] FORMERR: NSID option in query "
			       "must not contain payload, continuing\n", req->uid);

	/* Sanity check, answer should have EDNS as well but who knows ... */
	if (req->answer->opt_rr == NULL)
		return ctx->state;

	if (knot_pkt_reserve(req->answer, KNOT_EDNS_OPTION_HDRLEN + config->local_nsid_len)
		!= KNOT_EOK) {
		kr_log_verbose("[%05u][nsid] unable to reserve space for NSID option, "
			       "skipping\n", req->uid);
		return ctx->state;
	}

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_NSID,
				 config->local_nsid_len, config->local_nsid,
				 &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
		kr_log_verbose("[%05u][nsid] unable to add NSID option\n", req->uid);
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
	}

	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *nsid_layer(struct kr_module *module)
{
	static kr_layer_api_t _layer = {
		.finish = &nsid_finish,
	};
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int nsid_init(struct kr_module *module) {
	struct nsid_config *config = malloc(sizeof(struct nsid_config));
	if (config == NULL)
		return kr_error(ENOMEM);
	config->local_nsid = NULL;
	config->local_nsid_len = 0;

	module->data = config;
	return kr_ok();
}

static char* nsid_name(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;
	struct nsid_config *config = module->data;
	if (args) {  /* set */
		/* API is not binary safe, we need to fix this one day */
		size_t arg_len = strlen(args);
		uint8_t *arg_copy = malloc(arg_len + 1);
		if (arg_copy == NULL)
			luaL_error(engine->L, "[nsid] error while allocating new NSID value\n");
		memcpy(arg_copy, args, arg_len);
		arg_copy[arg_len] = '\0';  /* for output */

		if (config->local_nsid != NULL)
			free(config->local_nsid);
		config->local_nsid = arg_copy;
		config->local_nsid_len = arg_len;
	}

	/* get */
	if (config->local_nsid != NULL)
		return json_encode_string((char *)config->local_nsid);
	else
		return NULL;
}

KR_EXPORT
struct kr_prop *nsid_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &nsid_name, "name", "Get or set local NSID value" },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_EXPORT
int nsid_deinit(struct kr_module *module) {
	struct nsid_config *config = module->data;
	if (config != NULL) {
		if (config->local_nsid != NULL)
			free(config->local_nsid);
		free(module->data);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(nsid);
