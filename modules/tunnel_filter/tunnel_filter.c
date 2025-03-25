/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file tunnel_filter.c
 * @brief blocks queries that are evaluated as DNS tunneling exfiltration
 */

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "libblcnn.h"
#include "lib/layer.h"
#include "lib/resolve.h"

#define MAX_PACKET_SIZE 300

static int create_exfiltration_answer(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (!answer)
		return ctx->state;

	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NXDOMAIN);
	knot_wire_clear_ad(answer->wire);

	kr_request_set_extended_error(req, KNOT_EDNS_EDE_BLOCKED,
			"A4CP: Potential DNS tunnelling exfiltration query");
	ctx->state = KR_STATE_DONE;
	return ctx->state;
}

static int infer(kr_layer_t *ctx)
{
	struct kr_module *module = ctx->api->data;
	TorchModule net = module->data;
	struct kr_request *req = ctx->req;
	uint8_t *packet = req->qsource.packet->wire;
	size_t packet_size = req->qsource.size;

	float ret = predict_packet(net, packet, packet_size);
	if (ret > 0.95)
		return create_exfiltration_answer(ctx);

	return ctx->state;
}

KR_EXPORT
int tunnel_filter_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.begin = &infer,
	};

	layer.data = module;
	module->layer = &layer;
	
	static const struct kr_prop props[] = {
		{ NULL, NULL, NULL }
	};
	module->props = props;

	TorchModule net = load_model("blcnn.pt");
	if (!net) 
		return kr_error(ENOMEM);

	module->data = net;
	return kr_ok();
}

KR_EXPORT
int tunnel_filter_deinit(struct kr_module *module)
{
	TorchModule net = module->data;
	if (net) {
		free_model(net);
		module->data = NULL;
	}
	return kr_ok();
}

KR_MODULE_EXPORT(tunnel_filter)
