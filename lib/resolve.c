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
#include "lib/layer/itercache.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"
#include "lib/layer/stats.h"

#ifndef NDEBUG
#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[reslv] " fmt, ## __VA_ARGS__)
#else
#define DEBUG_MSG(fmt, ...)
#endif

/* Defines */
#define ITER_LIMIT 50

/*! \brief Invalidate current NS in cache. */
static int invalidate_ns(struct kr_rplan *rplan, struct kr_query *qry)
{
	namedb_txn_t *txn = kr_rplan_txn_acquire(rplan, 0);
	if (txn == NULL) {
		return KNOT_EOK;
	}
	
	/* Fetch current nameserver cache. */
	uint32_t drift = qry->timestamp.tv_sec;
	knot_rrset_t cached;
	knot_rrset_init(&cached, qry->zone_cut.name, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	if (kr_cache_peek(txn, &cached, &drift) != KNOT_EOK) {
		kr_init_zone_cut(&qry->zone_cut);
		return KNOT_EOK;
	}
	cached = kr_cache_materialize(&cached, drift, rplan->pool);
	
	/* Find a matching RD. */
	knot_rdataset_t to_remove;
	knot_rdataset_init(&to_remove);
	for (unsigned i = 0; i < cached.rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&cached.rrs, i);
		if (knot_dname_is_equal(knot_rdata_data(rd), qry->zone_cut.ns)) {
			knot_rdataset_add(&to_remove, rd, rplan->pool);
		}
	}
	knot_rdataset_subtract(&cached.rrs, &to_remove, rplan->pool);
	knot_rdataset_clear(&to_remove, rplan->pool);
	
	/* Remove record(s) */
	if (cached.rrs.rr_count == 0) {
		(void) kr_cache_remove(txn, &cached);
	} else {
		(void) kr_cache_insert(txn, &cached, qry->timestamp.tv_sec);
	}
	knot_rrset_clear(&cached, rplan->pool);

	/* Update zone cut and continue. */
	return kr_find_zone_cut(&qry->zone_cut, qry->sname, txn, qry->timestamp.tv_sec);
}

static int iterate(struct knot_requestor *requestor, struct kr_layer_param *param)
{
	int ret = KNOT_EOK;
	struct timeval timeout = { KR_CONN_RTT_MAX / 1000, 0 };
	struct kr_rplan *rplan = param->rplan;
	struct kr_query *cur = kr_rplan_current(rplan);

	/* Invalid address for current zone cut. */
	if (sockaddr_len((struct sockaddr *)&cur->zone_cut.addr) < 1) {
		return invalidate_ns(rplan, cur);
	}

	/* Prepare query resolution. */
	int mode = (cur->flags & QUERY_TCP) ? 0 : KNOT_RQ_UDP;
	struct sockaddr *ns_addr = (struct sockaddr *)&cur->zone_cut.addr;
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	struct knot_request *tx = knot_request_make(requestor->mm, ns_addr, NULL, query, mode);
	knot_requestor_enqueue(requestor, tx);

	/* Resolve and check status. */
	ret = knot_requestor_exec(requestor, &timeout);
	if (ret != KNOT_EOK) {
		/* Check if any query is left. */
		cur = kr_rplan_current(rplan);
		if (cur == NULL) {
			return ret;
		}
		/* Network error, retry over TCP. */
		if (ret != KNOT_LAYER_ERROR && !(cur->flags & QUERY_TCP)) {
			cur->flags |= QUERY_TCP;
			return iterate(requestor, param);
		}
		/* Resolution failed, invalidate current NS and reset to UDP. */
		ret = invalidate_ns(rplan, cur);
		cur->flags &= ~QUERY_TCP;
	}

	return ret;
}

static int resolve_iterative(struct kr_layer_param *param, mm_ctx_t *pool)
{
	/* Initialize requestor and overlay. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, pool);
	knot_requestor_overlay(&requestor, LAYER_STATIC, param);
	knot_requestor_overlay(&requestor, LAYER_ITERCACHE, param);
	knot_requestor_overlay(&requestor, LAYER_ITERATE, param);
	knot_requestor_overlay(&requestor, LAYER_STATS, param);

	/* Iteratively solve the query. */
	int ret = KNOT_EOK;
	unsigned iter_count = 0;
	while((ret == KNOT_EOK) && !kr_rplan_empty(param->rplan)) {
		ret = iterate(&requestor, param);
		if (++iter_count > ITER_LIMIT) {
			DEBUG_MSG("iteration limit %d reached => SERVFAIL\n", ITER_LIMIT);
			ret = KNOT_ELIMIT;
		}
	}

	/* Set RCODE on internal failure. */
	if (ret != KNOT_EOK) {
		if (knot_wire_get_rcode(param->answer->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(param->answer->wire, KNOT_RCODE_SERVFAIL);
		}
	}

	knot_requestor_clear(&requestor);
	return ret;
}

int kr_resolve(struct kr_context* ctx, knot_pkt_t *answer,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || answer == NULL || qname == NULL) {
		return KNOT_EINVAL;
	}

	/* Initialize context. */
	int ret = KNOT_EOK;
	mm_ctx_t rplan_pool;
	mm_ctx_mempool(&rplan_pool, MM_DEFAULT_BLKSIZE);
	struct kr_rplan rplan;
	kr_rplan_init(&rplan, ctx, &rplan_pool);
	struct kr_layer_param param;
	param.ctx = ctx;
	param.rplan = &rplan;
	param.answer = answer;

	/* Push query to resolution plan. */
	struct kr_query *qry = kr_rplan_push(&rplan, NULL, qname, qclass, qtype);
	if (qry != NULL) {
		ret = resolve_iterative(&param, &rplan_pool);
	} else {
		ret = KNOT_ENOMEM;
	}

	/* Check flags. */
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);

	/* Resolution success, commit cache transaction. */
	if (ret == KNOT_EOK) {
		kr_rplan_txn_commit(&rplan);
	}

	/* Clean up. */
	kr_rplan_deinit(&rplan);
	mp_delete(rplan_pool.ctx);

	return ret;
}
