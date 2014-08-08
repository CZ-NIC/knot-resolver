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

#include "daemon/layer/query.h"
#include "lib/resolve.h"

/* State-less single resolution iteration step, not needed. */
static int reset(knot_process_t *ctx)  { return NS_PROC_MORE; }
static int finish(knot_process_t *ctx) { return NS_PROC_NOOP; }
static int begin(knot_process_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return NS_PROC_MORE;
}

static int input_query(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct layer_param *param = ctx->data;

	/* Check if at least header is parsed. */
	if (pkt->parsed < pkt->size) {
		knot_pkt_free(&pkt);
		return NS_PROC_FAIL;
	}

	/* Accept only queries. */
	if (knot_wire_get_qr(pkt->wire)) {
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP; /* Ignore. */
	}

	/* Prepare for query processing. */
	int ret = kr_resolve(param->ctx, param->result,
	                     knot_pkt_qname(pkt),
	                     knot_pkt_qclass(pkt),
	                     knot_pkt_qtype(pkt));

	/* Set correct message ID. */
	knot_pkt_t *answer = param->result->ans;
	knot_wire_set_id(answer->wire, knot_wire_get_id(pkt->wire));

	/* Free query and finish. */
	knot_pkt_free(&pkt);

	if (ret != 0) {
		return NS_PROC_FAIL;
	} else {
		return NS_PROC_DONE;
	}
}

static int output(knot_pkt_t *pkt, knot_process_t *ctx)
{
	/* \note Output is returned indirectly via resolution result. */
	return NS_PROC_NOOP;
}

/*! \brief Module implementation. */
static const knot_process_module_t LAYER_QUERY_MODULE = {
	&begin,
	&reset,
	&finish,
	&input_query,
	&output,
	&knot_process_noop  /* No error processing. */
};

const knot_process_module_t *layer_query_module(void)
{
	return &LAYER_QUERY_MODULE;
}
