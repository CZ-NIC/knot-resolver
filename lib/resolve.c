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

#include <stdio.h>

#include <libknot/internal/mempool.h>
#include <libknot/processing/requestor.h>
#include <libknot/descriptor.h>
#include <libknot/dnssec/random.h>

#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/layer/itercache.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"
#include "lib/layer/stats.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[reslv] " fmt, ## __VA_ARGS__)

/* Defines */
#define ITER_LIMIT 50

/*! \brief Invalidate current NS in cache. */
static int invalidate_ns(struct kr_rplan *rplan, const struct kr_query *qry)
{
	namedb_txn_t *txn = kr_rplan_txn_acquire(rplan, 0);
	if (txn == NULL) {
		return KNOT_EOK;
	}

	/* TODO: selective removal */
	knot_rrset_t removed_rr;
	knot_rrset_init(&removed_rr, rplan->zone_cut.ns, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	(void) kr_cache_remove(txn, &removed_rr);

	/* Find new zone cut / nameserver */
	kr_find_zone_cut(&rplan->zone_cut, qry->sname, txn, qry->timestamp.tv_sec);

	/* Continue with querying */
	return KNOT_EOK;
}

static int iterate(struct knot_requestor *requestor, struct kr_layer_param *param)
{
	int ret = KNOT_EOK;
	struct timeval timeout = { KR_CONN_RTT_MAX / 1000, 0 };
	struct kr_rplan *rplan = param->rplan;
	const struct kr_query *cur = kr_rplan_current(rplan);

	/* Invalid address for current zone cut. */
	if (rplan->zone_cut.addr.ss_family == AF_UNSPEC) {
		return invalidate_ns(rplan, cur);
	}

	/* Prepare query resolution. */
	struct sockaddr *ns_addr = (struct sockaddr *)&rplan->zone_cut.addr;
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	struct knot_request *tx = knot_request_make(requestor->mm, ns_addr, NULL, query, 0);
	knot_requestor_enqueue(requestor, tx);

	/* Resolve and check status. */
	ret = knot_requestor_exec(requestor, &timeout);
	if (ret != KNOT_EOK) {
		/* Resolution failed, invalidate current NS. */
		ret = invalidate_ns(rplan, cur);
	}

	return ret;
}

int kr_resolve(struct kr_context* ctx, knot_pkt_t *answer,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || answer == NULL || qname == NULL) {
		return KNOT_ENOENT;
	}

	/* Initialize context. */
	mm_ctx_t rplan_pool;
	mm_ctx_mempool(&rplan_pool, MM_DEFAULT_BLKSIZE);
	struct kr_rplan rplan;
	kr_rplan_init(&rplan, ctx, &rplan_pool);

	/* Push query to resolve plan and set initial zone cut. */
	struct kr_query *qry = kr_rplan_push(&rplan, qname, qclass, qtype);
	namedb_txn_t *txn = kr_rplan_txn_acquire(&rplan, NAMEDB_RDONLY);
	kr_find_zone_cut(&rplan.zone_cut, qname, txn, qry->timestamp.tv_sec);

	struct kr_layer_param param;
	param.ctx = ctx;
	param.rplan = &rplan;
	param.answer = answer;

	/* Initialize requestor and overlay. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, ctx->pool);
	knot_requestor_overlay(&requestor, LAYER_STATIC, &param);
	knot_requestor_overlay(&requestor, LAYER_ITERCACHE, &param);
	knot_requestor_overlay(&requestor, LAYER_ITERATE, &param);
	knot_requestor_overlay(&requestor, LAYER_STATS, &param);

	/* Iteratively solve the query. */
	int ret = KNOT_EOK;
	unsigned iter_count = 0;
	while((ret == KNOT_EOK) && !kr_rplan_empty(&rplan)) {
		ret = iterate(&requestor, &param);
		if (++iter_count > ITER_LIMIT) {
			DEBUG_MSG("iteration limit %d reached => SERVFAIL\n", ITER_LIMIT);
			ret = KNOT_ELIMIT;
		}
	}

	knot_requestor_clear(&requestor);

	/* Resolution success, commit cache transaction. */
	if (ret == KNOT_EOK) {
		kr_rplan_txn_commit(&rplan);
	} else {
		/* Set RCODE on internal failure. */
		if (knot_wire_get_rcode(answer->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
		}
	}

	/* Clean up. */
	kr_rplan_deinit(&rplan);
	mp_delete(rplan_pool.ctx);

	return ret;
}
