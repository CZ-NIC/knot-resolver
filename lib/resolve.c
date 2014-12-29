#include <stdio.h>

#include <libknot/internal/mempool.h>
#include <libknot/processing/requestor.h>
#include <libknot/descriptor.h>
#include <libknot/dnssec/random.h>

#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"
#include "lib/layer/stats.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[reslv] " fmt, ## __VA_ARGS__)

/* Defines */
#define ITER_LIMIT 50

/*! \brief Fetch address record for nameserver. */
static int prefetch_ns_addr(struct kr_rplan *rplan, const struct timeval *now)
{
	namedb_txn_t *txn = kr_rplan_txn_acquire(rplan, NAMEDB_RDONLY);
	struct kr_zonecut *cut = &rplan->zone_cut;

	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)cut->name, KNOT_RRTYPE_A, KNOT_CLASS_IN);

	/* Fetch nameserver address from cache. */
	uint32_t timestamp = now->tv_sec;
	if (kr_cache_query(txn, &cached_rr, &timestamp) != KNOT_EOK) {
		cached_rr.type = KNOT_RRTYPE_AAAA;
		if (kr_cache_query(txn, &cached_rr, &timestamp) != KNOT_EOK) {
			return KNOT_ENOENT;
		}
	}

	/* Update nameserver address if found. */
	return kr_rrset_to_addr(&cut->addr, &cached_rr);
}

/*! \brief Plan NS address resolution. */
static int plan_ns_addr_fetch(struct kr_rplan *rplan)
{
	/* TODO: implement rplan states to iteratively scan for A and then AAAA */
	(void) kr_rplan_push(rplan, rplan->zone_cut.ns, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	(void) kr_rplan_push(rplan, rplan->zone_cut.ns, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA);

	/* Reset zone cut for current query. */
	struct kr_query *last = kr_rplan_last(rplan);
	namedb_txn_t *txn = kr_rplan_txn_acquire(rplan, NAMEDB_RDONLY);
	return kr_find_zone_cut(&rplan->zone_cut, KR_DNAME_ROOT, txn, last->timestamp.tv_sec);
}

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

	/* Retrieve address for current zone cut. */
	if (rplan->zone_cut.addr.ss_family == AF_UNSPEC) {
		ret = prefetch_ns_addr(rplan, &cur->timestamp);
		if (ret != KNOT_EOK) {
			plan_ns_addr_fetch(rplan);
			return KNOT_EOK;
		}
	}

	char name_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(ns_str, rplan->zone_cut.ns, sizeof(ns_str));
	knot_dname_to_str(zonecut_str, rplan->zone_cut.name, sizeof(zonecut_str));
	knot_dname_to_str(name_str, cur->sname, sizeof(name_str));
	knot_rrtype_to_string(cur->stype, type_str, sizeof(type_str));
	DEBUG_MSG("resolve '%s %s' zone cut '%s' nameserver '%s'\n", name_str, type_str, zonecut_str, ns_str);

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
