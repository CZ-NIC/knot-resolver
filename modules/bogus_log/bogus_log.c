/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
 *
 * This module logs (query name, type) pairs which failed DNSSEC validation. */

#include <libknot/packet/pkt.h>
#include <contrib/cleanup.h>

#include "daemon/engine.h"
#include "lib/layer.h"

static int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (!(ctx->state & KR_STATE_FAIL)
	    || !ctx->req
	    || !ctx->req->current_query
	    || !ctx->req->current_query->flags.DNSSEC_BOGUS
	    || knot_wire_get_qdcount(pkt->wire) != 1)
		return ctx->state;

	auto_free char *qname_text = kr_dname_text(knot_pkt_qname(pkt));
	auto_free char *qtype_text = kr_rrtype_text(knot_pkt_qtype(pkt));

	kr_log_error("DNSSEC validation failure %s %s\n", qname_text, qtype_text);
	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *bogus_log_layer(struct kr_module *module)
{
	static kr_layer_api_t _layer = {
		.consume = &consume,
	};
	_layer.data = module;
	return &_layer;
}

KR_MODULE_EXPORT(bogus_log)
