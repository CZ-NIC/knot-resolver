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

static void update_ns_preference(struct kr_ns *ns, struct kr_ns *next)
{
	assert(ns);
	assert(next);

	/* Push down if next has better score. */
	if (next->stat.M < ns->stat.M) {
		rem_node(&ns->node);
		insert_node(&ns->node, &next->node);
	}
}

static void update_ns_preference_list(struct kr_ns *cur)
{
	assert(cur);
	struct kr_ns *next = (struct kr_ns *)cur->node.next;

	/* O(n), walk the list (shouldn't be too large). */
	/* TODO: cut on first swap? random swaps? */
	while (next->node.next != NULL) {
		update_ns_preference(cur, next);
		cur  = next;
		next = (struct kr_ns *)cur->node.next;
	}
}

static void update_stats(struct kr_ns *ns, double rtt)
{
	/* Knuth, TAOCP, p.232 (Welford running variance/mean). */
	double d_mean = (rtt - ns->stat.M);
	ns->stat.n += 1;
	ns->stat.M += d_mean / ns->stat.n;
	ns->stat.S += d_mean * (rtt - ns->stat.M);

	/* Update NS position in preference list. */
	update_ns_preference_list(ns);
}

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
	char qnamestr[KNOT_DNAME_MAXLEN] = { '\0' };
	knot_dname_to_str(qnamestr, knot_pkt_qname(result->ans), sizeof(qnamestr) - 1);
	DEBUG_MSG("resolution of %s\n", qnamestr);
	DEBUG_MSG("rcode: %d (%u RRs)\n", knot_wire_get_rcode(result->ans->wire), result->ans->rrset_count);
	DEBUG_MSG("queries: %u\n", result->nr_queries);
	DEBUG_MSG("total time: %u msecs\n", result->total_rtt);
#endif

	return ctx->state;
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_result *result = param->result;

	result->nr_queries += 1;

	/* Store stats. */
	gettimeofday(&result->t_start, NULL);

	return ctx->state;
}

static int answer(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_context* resolve = param->ctx;
	struct kr_result *result = param->result;
	struct kr_ns *ns = resolve->current_ns;

	/* Store stats. */
	gettimeofday(&result->t_end, NULL);

	/* Update NS statistics. */
	double rtt = time_diff(&result->t_start, &result->t_end);
	if (rtt > 0.0) {
		update_stats(ns, rtt);
		result->total_rtt += rtt;
	}

#ifndef NDEBUG
	char ns_name[KNOT_DNAME_MAXLEN] = { '\0' };
	knot_dname_to_str(ns_name, ns->name, sizeof(ns_name) - 1);
	char pad[16];
	memset(pad, '-', sizeof(pad));
	int pad_len = list_size(&resolve->rplan.q) * 2;
	if (pad_len > sizeof(pad) - 1) {
		pad_len = sizeof(pad) - 1;
	}
	DEBUG_MSG("#%s %s ... RC=%d, AA=%d, RTT: %.02f msecs\n",
	          pad, ns_name, knot_wire_get_rcode(pkt->wire),
	          knot_wire_get_aa(pkt->wire) != 0,
	          rtt);
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
