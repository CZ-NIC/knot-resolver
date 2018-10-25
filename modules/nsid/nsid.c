/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
 *
 * This module provides NSID support according to RFC 5001. */

#include <libknot/packet/pkt.h>
#include <contrib/cleanup.h>

#include "daemon/engine.h"
#include "lib/layer.h"


static int nsid_finish(kr_layer_t *ctx) {
	struct kr_request *req = ctx->req;
	const knot_pkt_t* answer = req->answer;
	const struct kr_module *module = ctx->api->data;
	const struct kr_rplan *rplan = &req->rplan;

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
	if (knot_edns_opt_get_length(req_nsid) != 0) {
		kr_log_verbose("FORMERR: NSID option in query must not have payload"); // TODO: better logging
		return ctx->state;
	}

	/* Sanity check, answer should have EDNS as well but who knows ... */
	if (req->answer->opt_rr == NULL)
		return ctx->state;

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_NSID, 4, (uint8_t *)"test", &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
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

KR_MODULE_EXPORT(nsid);
