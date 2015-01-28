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

#include <libknot/internal/print.h>

#include "lib/layer/stats.h"
#include "lib/rplan.h"

#ifndef NDEBUG
#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[stats] " fmt, ## __VA_ARGS__)
#else
#define DEBUG_MSG(fmt, ...)
#endif

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
#ifndef NDEBUG
	struct kr_layer_param *param = ctx->data;
	struct kr_rplan *rplan = param->rplan;
	const knot_pkt_t *answer = param->answer;

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
