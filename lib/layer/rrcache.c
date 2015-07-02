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

#include <libknot/descriptor.h>
#include <libknot/errcode.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>
#include <libknot/internal/mempool.h>
#include <libknot/rrtype/rdname.h>

#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), " rc ",  fmt)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int loot_rrsig(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *name,
                      uint16_t rrclass, uint16_t typec, struct kr_query *qry)
{
	if (KNOT_RRTYPE_RRSIG == typec) {
		return kr_ok();
	}

	/* Check if RRSIG record exists in cache. */
	uint32_t timestamp = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, typec, rrclass);
	int ret = kr_cache_peek_rrsig(txn, &cache_rr, &timestamp);
	if (0 != ret) {
		return ret;
	}

	/* Update packet answer */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cache_rr, timestamp, &pkt->mm);
	if (0 == ret) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &rr_copy, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_clear(&rr_copy, &pkt->mm);
		}
	}
	return ret;
}

static int loot_rr(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry, bool dobit)
{
	/* Check if record exists in cache */
	uint32_t timestamp = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, rrtype, rrclass);
	int ret = kr_cache_peek_rr(txn, &cache_rr, &timestamp);
	if (ret != 0) {
		return ret;
	}

	/* Update packet question */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)) {
		KR_PKT_RECYCLE(pkt);
		knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
	}

	/* Update packet answer */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cache_rr, timestamp, &pkt->mm);
	if (ret == 0) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &rr_copy, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_clear(&rr_copy, &pkt->mm);
		}
	}
	if (dobit) {
		ret = loot_rrsig(txn, pkt, name, rrclass, rrtype, qry);
	}
	return ret;
}

/** @internal Try to find a shortcut directly to searched record. */
static int loot_cache(struct kr_cache *cache, knot_pkt_t *pkt, struct kr_query *qry, bool dobit)
{
	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY);
	if (ret != 0) {
		return ret;
	}
	/* Lookup direct match first */
	ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, qry->stype, qry, dobit);
	if (ret != 0 && qry->stype != KNOT_RRTYPE_CNAME) { /* Chase CNAME if no direct hit */
		ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, KNOT_RRTYPE_CNAME, qry, dobit);
	}
	kr_cache_txn_abort(&txn);
	return ret;
}

static int peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE)) {
		return ctx->state; /* Already resolved/failed */
	}
	if (!(qry->flags & QUERY_AWAIT_CUT)) {
		return ctx->state; /* Only lookup on first iteration */
	}

	bool dobit = knot_pkt_has_dnssec(req->answer);

	/* Reconstruct the answer from the cache,
	 * it may either be a CNAME chain or direct answer.
	 * Only one step of the chain is resolved at a time.
	 */
	struct kr_cache *cache = &req->ctx->cache;
	int ret = loot_cache(cache, pkt, qry, dobit);
	if (ret == 0) {
		DEBUG_MSG("=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KNOT_STATE_DONE;
	}
	return ctx->state;
}

/** @internal Stashed data container. */
struct stash_data
{
	map_t rrs;
	map_t rrsigs;
};

static void stash_data_init(struct stash_data *stashd, mm_ctx_t *pool)
{
	stashd->rrs = map_make();
	stashd->rrs.malloc = (map_alloc_f) mm_alloc;
	stashd->rrs.free = (map_free_f) mm_free;
	stashd->rrs.baton = pool;

	stashd->rrsigs = map_make();
	stashd->rrsigs.malloc = (map_alloc_f) mm_alloc;
	stashd->rrsigs.free = (map_free_f) mm_free;
	stashd->rrsigs.baton = pool;
}

/** @internal Baton for stash_commit */
struct stash_baton
{
	struct kr_cache_txn *txn;
	unsigned timestamp;
};

static int commit_rrsig(const char *key, void *val, void *data)
{
	/* Insert RRSIGs in special cache. */
	knot_rrset_t *rrsig = val;
	struct stash_baton *baton = data;
	if (knot_rrset_ttl(rrsig) < 1) {
		return kr_ok(); /* Ignore cache busters */
	}
	/* Check if already cached */
	/** @todo This should check if less trusted data is in the cache,
	          for that the cache would need to trace data trust level.
	   */
	/* Check if already cached */
	unsigned drift = baton->timestamp;
	knot_rrset_t query_rrsig;
	knot_rrset_init(&query_rrsig, rrsig->owner, rrsig->type, rrsig->rclass);
	if (kr_cache_peek_rrsig(baton->txn, &query_rrsig, &drift) == 0) {
		return kr_ok();
	}
	return kr_cache_insert_rrsig(baton->txn, rrsig, rrsig->type, baton->timestamp);
}

static int commit_rr(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct stash_baton *baton = data;
	if (knot_rrset_ttl(rr) < 1) {
		return kr_ok(); /* Ignore cache busters */
	}
	/* Check if already cached */
	/** @todo This should check if less trusted data is in the cache,
	          for that the cache would need to trace data trust level.
	   */
	unsigned drift = baton->timestamp;
	knot_rrset_t query_rr;
	knot_rrset_init(&query_rr, rr->owner, rr->type, rr->rclass);
	if (kr_cache_peek_rr(baton->txn, &query_rr, &drift) == 0) {
	        return kr_ok();
	}
	return kr_cache_insert_rr(baton->txn, rr, baton->timestamp);
}

static int stash_commit(struct stash_data *stash, unsigned timestamp, struct kr_cache_txn *txn)
{
	struct stash_baton baton = {
		.txn = txn,
		.timestamp = timestamp
	};
	int ret = map_walk(&stash->rrs, &commit_rr, &baton);
	if (ret == 0) {
		ret = map_walk(&stash->rrsigs, &commit_rrsig, &baton);
	}
	return ret;
}

static int merge_in_rrsigs(knot_rrset_t *cache_rr, const knot_rrset_t *rrsigset, const knot_rrset_t *rr,
                           mm_ctx_t *pool)
{
	int ret = KNOT_EOK;

	/* Find rrset corresponding to RRSIG. */
	for (unsigned i = 0; i < rrsigset->rrs.rr_count; ++i) {
		if ((knot_rrsig_type_covered(&rrsigset->rrs, i) == rr->type) &&
		    knot_dname_is_equal(cache_rr->owner, rrsigset->owner)) {
			const knot_rdata_t *rdata = knot_rdataset_at(&rrsigset->rrs, i);
			ret = knot_rdataset_add(&cache_rr->rrs, rdata, pool);
			if (KNOT_EOK != ret) {
				return ret;
			}
		}
	}

	return ret;
}

static int scan_for_rrsigs(knot_rrset_t *cache_rrsig, const knot_pktsection_t *section,
                           const knot_rrset_t *rr, mm_ctx_t *pool)
{
	knot_rrset_init(cache_rrsig, rr->owner, rr->type, rr->rclass);
	for (uint16_t i = 0; i < section->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(section, i);
		if (KNOT_RRTYPE_RRSIG != rrset->type) {
			continue;
		}
		int ret = merge_in_rrsigs(cache_rrsig, rrset, rr, pool);
		if (KNOT_EOK != ret) {
			knot_rrset_clear(cache_rrsig, pool);
			return ret;
		}
	}

	return kr_ok();
}

static int stash_add_rrsig(const knot_pktsection_t *section, map_t *stash,
                           const knot_rrset_t *rr, mm_ctx_t *pool)
{
	/* Can't store RRSIG of RRSIG. */
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		return kr_ok();
	}

	/* Stash key = {[1-255] owner, [1-5] type covered, [1] \x00 } */
	char key[8 + KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire((uint8_t *)key, rr->owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower((uint8_t *)key);
	ret = snprintf(key + ret - 1, sizeof(key) - KNOT_DNAME_MAXLEN, "%hu", rr->type);
	if (ret <= 0 || ret >= KNOT_DNAME_MAXLEN) {
		return kr_error(EILSEQ);
	}

	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (stashed) {
		return kr_ok();
	}

	/* Construct RRSIG RRSet containing related data. */
	knot_rrset_t cache_rrsig;
	ret = scan_for_rrsigs(&cache_rrsig, section, rr, pool);
	if (ret != 0) {
		return ret;
	}

	if (cache_rrsig.rrs.rr_count) {
		stashed = knot_rrset_copy(&cache_rrsig, pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
	}
	knot_rrset_clear(&cache_rrsig, pool);
	if (stashed) {
		return map_set(stash, key, stashed);
	}
	return kr_ok();
}

static int stash_add(const knot_pkt_t *pkt, map_t *stash, const knot_rrset_t *rr, mm_ctx_t *pool)
{
	/* Do not stash DNSSEC data if not secured. */
	bool dobit = knot_pkt_has_dnssec(pkt);
	if (!dobit && knot_rrtype_is_dnssec(rr->type)) {
		return kr_ok();
	}

	/* Do not stash alone RRSIGs, these must be stashed together with signed RRs. */
	if (dobit && (rr->type == KNOT_RRTYPE_RRSIG)) {
		return kr_ok();
	}

	/* Stash key = {[1-255] owner, [1-5] type, [1] \x00 } */
	char key[8 + KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire((uint8_t *)key, rr->owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower((uint8_t *)key);
	ret = snprintf(key + ret - 1, sizeof(key) - KNOT_DNAME_MAXLEN, "%hu", rr->type);
	if (ret <= 0 || ret >= KNOT_DNAME_MAXLEN) {
		return kr_error(EILSEQ);
	}
	
	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (!stashed) {
		stashed = knot_rrset_copy(rr, pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
		return map_set(stash, key, stashed);
	}
	/* Merge rdataset */
	return knot_rdataset_merge(&stashed->rrs, &rr->rrs, pool);
}

static void stash_glue(struct stash_data *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, mm_ctx_t *pool)
{
	const knot_pktsection_t *additional = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < additional->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(additional, i);
		if ((rr->type != KNOT_RRTYPE_A && rr->type != KNOT_RRTYPE_AAAA) ||
		    !knot_dname_is_equal(rr->owner, ns_name)) {
			continue;
		}
		stash_add(pkt, &stash->rrs, rr, pool);
	}
}

static int stash_authority(struct kr_query *qry, knot_pkt_t *pkt, struct stash_data *stash, mm_ctx_t *pool)
{
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		/* Cache in-bailiwick data only */
		if (!knot_dname_in(qry->zone_cut.name, rr->owner)) {
			continue;
		}
		/* Look up glue records for NS */
		if (rr->type == KNOT_RRTYPE_NS) {
			stash_glue(stash, pkt, knot_ns_name(&rr->rrs, 0), pool);
		}
		/* Stash record */
		stash_add(pkt, &stash->rrs, rr, pool);
		stash_add_rrsig(authority, &stash->rrsigs, rr, pool);
	}
	return kr_ok();
}

static int stash_answer(struct kr_query *qry, knot_pkt_t *pkt, struct stash_data *stash, mm_ctx_t *pool)
{
	const knot_dname_t *cname = qry->sname;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < answer->count; ++i) {
		/* Stash direct answers (equal to current QNAME/CNAME) */
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (!knot_dname_is_equal(rr->owner, cname)) {
			continue;
		}
		stash_add(pkt, &stash->rrs, rr, pool);
		stash_add_rrsig(answer, &stash->rrsigs, rr, pool);
		/* Follow CNAME chain */
		if (rr->type == KNOT_RRTYPE_CNAME) {
			cname = knot_cname_name(&rr->rrs);
		} else {
			cname = qry->sname;
		}
	}
	return kr_ok();
}

static int stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Cache only positive answers. */
	if (qry->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return ctx->state;
	}
	/* Stash in-bailiwick data from the AUTHORITY and ANSWER. */
	struct stash_data stash;
	stash_data_init(&stash, rplan->pool);
	int ret = stash_authority(qry, pkt, &stash, rplan->pool);
	if (ret == 0 && knot_wire_get_aa(pkt->wire)) {
		ret = stash_answer(qry, pkt, &stash, rplan->pool);
	}
	/* Cache stashed records */
	if (ret == 0) {
		/* Open write transaction */
		struct kr_cache *cache = &req->ctx->cache;
		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
			ret = stash_commit(&stash, qry->timestamp.tv_sec, &txn);
			if (ret == 0) {
				kr_cache_txn_commit(&txn);
			} else {
				kr_cache_txn_abort(&txn);
			}
		}
		/* Clear if full */
		if (ret == KNOT_ESPACE) {
			if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
				ret = kr_cache_clear(&txn);
				if (ret == 0) {
					kr_cache_txn_commit(&txn);
				} else {
					kr_cache_txn_abort(&txn);
				}
			}
		}
	}
	
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *rrcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.produce = &peek,
		.consume = &stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrcache)
