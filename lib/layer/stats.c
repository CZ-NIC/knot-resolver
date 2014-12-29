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

#include <libknot/internal/print.h>

#include "lib/layer/stats.h"
#include "lib/rplan.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[stats] " fmt, ## __VA_ARGS__)

//static void update_stats(struct kr_ns *ns, double rtt)
//{
//	/* Knuth, TAOCP, p.232 (Welford running variance/mean). */
//	double d_mean = (rtt - ns->stat.M);
//	ns->stat.n += 1;
//	ns->stat.M += d_mean / ns->stat.n;
//	ns->stat.S += d_mean * (rtt - ns->stat.M);
//}

static int begin(knot_layer_t *ctx, void *param)
{
	ctx->data = param;
	return ctx->state;
}

static int finish(knot_layer_t *ctx)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_rplan *rplan = param->rplan;
	const knot_pkt_t *answer = param->answer;

#ifndef NDEBUG
	/* Calculate total RTT and number of queries. */
	double total_rtt = 0.0;
	size_t nr_queries = list_size(&rplan->resolved);
	if (nr_queries > 0) {
		struct kr_query *query_first = HEAD(rplan->resolved);
		struct timeval t_end;
		gettimeofday(&t_end, NULL);
		total_rtt = time_diff(&query_first->timestamp, &t_end);
	}

	lookup_table_t *rcode = lookup_by_id(knot_rcode_names, knot_wire_get_rcode(answer->wire));
	DEBUG_MSG("result => %s [%u records]\n", rcode ? rcode->name : "??", answer->rrset_count);
	DEBUG_MSG("rtt => %.02lf [ms]\n",  total_rtt);
#endif

	return ctx->state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_STATS_MODULE = {
	&begin,
	NULL,
	&finish,
	NULL,
	NULL,
	NULL
};

const knot_layer_api_t *layer_stats_module(void)
{
	return &LAYER_STATS_MODULE;
}
