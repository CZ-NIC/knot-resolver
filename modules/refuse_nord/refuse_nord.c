/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
 *
 * This module responds to all queries without RD bit set with REFUSED. */

#include <libknot/consts.h>
#include <libknot/packet/pkt.h>
#include "daemon/worker.h"
#include "lib/module.h"
#include "lib/layer.h"

static int refuse_nord_query(kr_layer_t *ctx, va_list ap /* none */)
{
	struct kr_request *req = ctx->req;
	uint8_t rd = knot_wire_get_rd(req->qsource.packet->wire);

	if (!rd) {
		knot_pkt_t *answer = req->answer;
		knot_wire_set_rcode(answer->wire, KNOT_RCODE_REFUSED);
		knot_wire_clear_ad(answer->wire);
		ctx->state = KR_STATE_DONE;
	}

	return ctx->state;
}

KR_EXPORT int refuse_nord_init(struct kr_module *module)
{
	static const kr_layer_api_t layer = {
		.funcs = {
			[SLOT_begin] = &refuse_nord_query,
		}
	};
	module->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(refuse_nord)
