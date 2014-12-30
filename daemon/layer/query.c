/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libknot/errcode.h>

#include "daemon/layer/query.h"
#include "lib/resolve.h"

static int reset(knot_layer_t *ctx)
{
	return KNOT_NS_PROC_MORE;
}

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return reset(ctx);
}

static int input_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);

	/* Check if at least header is parsed. */
	if (pkt->parsed < pkt->size) {
		return KNOT_NS_PROC_FAIL;
	}

	/* Accept only queries. */
	if (knot_wire_get_qr(pkt->wire)) {
		return KNOT_NS_PROC_NOOP; /* Ignore. */
	}

	return KNOT_NS_PROC_FULL;
}

static int output_answer(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);

	/* Prepare for query processing. */
	int ret = kr_resolve(ctx->data, pkt,
	                     knot_pkt_qname(pkt),
	                     knot_pkt_qclass(pkt),
	                     knot_pkt_qtype(pkt));

	if (ret != KNOT_EOK) {
		return KNOT_NS_PROC_FAIL;
	}

	return KNOT_NS_PROC_DONE;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_QUERY_MODULE = {
	&begin,
	NULL,
	&reset,
	&input_query,
	&output_answer,
	NULL
};

const knot_layer_api_t *layer_query_module(void)
{
	return &LAYER_QUERY_MODULE;
}
