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

#include <common/print.h>

#include "lib/layer/stats.h"
#include "lib/rplan.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[stats] " fmt, ## __VA_ARGS__)

static int begin(knot_layer_t *ctx, void *param)
{
	ctx->data = param;
	return ctx->state;
}

static int finish(knot_layer_t *ctx)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_result *result = param->result;

#ifndef NDEBUG
	char *qnamestr = knot_dname_to_str(knot_pkt_qname(result->ans));
	DEBUG_MSG("resolution of %s\n", qnamestr);
	free(qnamestr);

	DEBUG_MSG("rcode: %d (%u RRs)\n", knot_wire_get_rcode(result->ans->wire), result->ans->rrset_count);
	DEBUG_MSG("queries: %u\n", result->nr_queries);
	DEBUG_MSG("total time: %.02f msecs\n", time_diff(&result->t_start, &result->t_end));
#endif

	return ctx->state;
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_result *result = param->result;

	result->nr_queries += 1;

	return ctx->state;
}

static int answer(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_context* resolve = param->ctx;
	struct kr_result *result = param->result;

	/* Store stats. */
	gettimeofday(&result->t_end, NULL);

#ifndef NDEBUG
	char *ns_name = knot_dname_to_str(resolve->current_ns->name);
	char pad[16];
	memset(pad, '-', sizeof(pad));
	pad[MIN(sizeof(pad) - 1, list_size(&resolve->rplan.q) * 2)] = '\0';
	DEBUG_MSG("#%s %s ... RC=%d, AA=%d, cumulative time: %.02f msecs\n",
	          pad, ns_name, knot_wire_get_rcode(pkt->wire),
	          knot_wire_get_aa(pkt->wire) != 0,
	          time_diff(&result->t_start, &result->t_end));
	free(ns_name);
#endif

	return ctx->state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_STATS_MODULE = {
	&begin,
	NULL,
	&finish,
	&answer,
	&query,
	NULL
};

const knot_layer_api_t *layer_stats_module(void)
{
	return &LAYER_STATS_MODULE;
}
