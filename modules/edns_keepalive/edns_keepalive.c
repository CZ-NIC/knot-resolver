/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file edns_keepalive.c
 * @brief Minimalistic EDNS keepalive implementation on server side.
 *        If keepalive option is present in query,
 *        always reply with constant timeout value.
 *
 */
#include <libknot/packet/pkt.h>
#include "daemon/worker.h"
#include "lib/module.h"
#include "lib/layer.h"

static int edns_keepalive_finalize(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	knot_pkt_t *answer = req->answer;
	const knot_rrset_t *src_opt = req->qsource.packet->opt_rr;
	knot_rrset_t *answ_opt = answer->opt_rr;

	const bool ka_want =
		req->qsource.flags.tcp &&
		src_opt != NULL &&
		knot_edns_get_option(src_opt, KNOT_EDNS_OPTION_TCP_KEEPALIVE, NULL) &&
		answ_opt != NULL;
	if (!ka_want) {
		return ctx->state;
	}
	uint64_t timeout = the_network->tcp.in_idle_timeout / 100;
	if (timeout > UINT16_MAX) {
		timeout = UINT16_MAX;
	}
	knot_mm_t *pool = &answer->mm;
	uint16_t ka_size = knot_edns_keepalive_size(timeout);
	uint8_t ka_buf[ka_size];
	int ret = knot_edns_keepalive_write(ka_buf, ka_size, timeout);
	if (ret == KNOT_EOK) {
		ret = knot_edns_add_option(answ_opt, KNOT_EDNS_OPTION_TCP_KEEPALIVE,
					   ka_size, ka_buf, pool);
	}
	if (ret != KNOT_EOK) {
		ctx->state = KR_STATE_FAIL;
	}
	return ctx->state;
}

KR_EXPORT int edns_keepalive_init(struct kr_module *self)
{
	static const kr_layer_api_t layer = {
		.answer_finalize = &edns_keepalive_finalize,
	};
	self->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(edns_keepalive)

