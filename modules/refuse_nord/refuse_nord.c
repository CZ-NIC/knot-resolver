/* Copyright (C) Knot Resolver contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This module responds to all queries without RD bit set with REFUSED. */

#include <libknot/consts.h>
#include <libknot/packet/pkt.h>
#include "daemon/worker.h"
#include "lib/module.h"
#include "lib/layer.h"

static int refuse_nord_query(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	uint8_t rd = knot_wire_get_rd(req->qsource.packet->wire);

	if (!rd) {
		knot_pkt_t *answer = kr_request_ensure_answer(req);
		knot_wire_set_rcode(answer->wire, KNOT_RCODE_REFUSED);
		knot_wire_clear_ad(answer->wire);
		ctx->state = KR_STATE_DONE;
	}

	return ctx->state;
}

KR_EXPORT int refuse_nord_init(struct kr_module *module)
{
	static const kr_layer_api_t layer = {
		.begin = &refuse_nord_query,
	};
	module->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(refuse_nord)
