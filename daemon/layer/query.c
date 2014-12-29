/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
