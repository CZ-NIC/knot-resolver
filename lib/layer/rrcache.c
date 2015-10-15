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
#include <libknot/rrtype/rdname.h>
#include <ucw/config.h>
#include <ucw/lib.h>

#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/module.h"
#include "lib/utils.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG((qry), " rc ",  fmt)
#define DEFAULT_MINTTL (5) /* Short-time "no data" retention to avoid bursts */

/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static inline bool is_expiring(const knot_rrset_t *rr, uint32_t drift)
{
	return 100 * (drift + 5) > 99 * knot_rrset_ttl(rr);
}

static int loot_rr(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry, uint16_t *rank, bool fetch_rrsig)
{
	/* Check if record exists in cache */
	int ret = 0;
	uint32_t drift = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, rrtype, rrclass);
	if (fetch_rrsig) {
		ret = kr_cache_peek_rrsig(txn, &cache_rr, rank, &drift);
	} else {
		ret = kr_cache_peek_rr(txn, &cache_rr, rank, &drift);
	}
	if (ret != 0) {
		return ret;
	}

	/* Mark as expiring if it has less than 1% TTL (or less than 5s) */
	if (is_expiring(&cache_rr, drift)) {
		qry->flags |= QUERY_EXPIRING;
	}

	/* Update packet question */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)) {
		KR_PKT_RECYCLE(pkt);
		knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
	}

	/* Update packet answer */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cache_rr, drift, &pkt->mm);
	if (ret == 0) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &rr_copy, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_clear(&rr_copy, &pkt->mm);
		}
	}
	return ret;
}

/** @internal Try to find a shortcut directly to searched record. */
static int loot_cache(struct kr_cache *cache, knot_pkt_t *pkt, struct kr_query *qry, uint16_t rrtype, bool dobit)
{
	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY);
	if (ret != 0) {
		return ret;
	}
	/* Lookup direct match first */
	uint16_t rank = 0;
	ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, 0);
	if (ret != 0 && rrtype != KNOT_RRTYPE_CNAME) { /* Chase CNAME if no direct hit */
		rrtype = KNOT_RRTYPE_CNAME;
		ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, 0);
	}
	/* Record isn't flagged as INSECURE => doesn't have RRSIG. */
	if (ret == 0 && (rank & KR_RANK_INSECURE)) {
		qry->flags &= ~QUERY_DNSSEC_WANT;
	/* Record may have RRSIG, try to find it. */
	} else if (ret == 0 && dobit) {
		ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, true);
	}
	kr_cache_txn_abort(&txn);
	return ret;
}

static int peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE) || (qry->flags & QUERY_NO_CACHE)) {
		return ctx->state; /* Already resolved/failed */
	}
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC) {
		return ctx->state; /* Only lookup before asking a query */
	}

	/* Reconstruct the answer from the cache,
	 * it may either be a CNAME chain or direct answer.
	 * Only one step of the chain is resolved at a time.
	 */
	struct kr_cache *cache = &req->ctx->cache;
	int ret = -1;
	if (qry->stype != KNOT_RRTYPE_ANY) {
		ret = loot_cache(cache, pkt, qry, qry->stype, (qry->flags & QUERY_DNSSEC_WANT));
	} else {
		/* ANY query are used by either qmail or certain versions of Firefox.
		 * Probe cache for a few interesting records. */
		static uint16_t any_types[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA, KNOT_RRTYPE_MX };
		for (size_t i = 0; i < sizeof(any_types)/sizeof(any_types[0]); ++i) {
			if (loot_cache(cache, pkt, qry, any_types[i], (qry->flags & QUERY_DNSSEC_WANT)) == 0) {
				ret = 0; /* At least single record matches */
			}
		}
	}
	if (ret == 0) {
		DEBUG_MSG(qry, "=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KNOT_STATE_DONE;
	}
	return ctx->state;
}

/** @internal Baton for stash_commit */
struct stash_baton
{
	struct kr_request *req;
	struct kr_query *qry;
	struct kr_cache_txn *txn;
	unsigned timestamp;
	uint32_t min_ttl;
};

static int commit_rrsig(struct stash_baton *baton, uint16_t rank, knot_rrset_t *rr)
{
	/* If not doing secure resolution, ignore (unvalidated) RRSIGs. */
	if (!(baton->qry->flags & QUERY_DNSSEC_WANT)) {
		return kr_ok();
	}
	/* Commit covering RRSIG to a separate cache namespace. */
	return kr_cache_insert_rrsig(baton->txn, rr, rank, baton->timestamp);
}

static int commit_rr(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct stash_baton *baton = data;
	/* Ensure minimum TTL */
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) < baton->min_ttl) {
			knot_rdata_set_ttl(rd, baton->min_ttl);
		}
		rd = kr_rdataset_next(rd);
	}

	/* Save RRSIG in a special cache. */
	uint16_t rank = KEY_FLAG_RANK(key);
	if (baton->qry->flags & QUERY_DNSSEC_WANT)
		rank |= KR_RANK_SECURE;
	if (baton->qry->flags & QUERY_DNSSEC_INSECURE)
		rank |= KR_RANK_INSECURE;
	if (KEY_COVERING_RRSIG(key)) {
		return commit_rrsig(baton, rank, rr);
	}

	/* Check if already cached */
	knot_rrset_t query_rr;
	knot_rrset_init(&query_rr, rr->owner, rr->type, rr->rclass);
	return kr_cache_insert_rr(baton->txn, rr, rank, baton->timestamp);
}

static int stash_commit(map_t *stash, struct kr_query *qry, struct kr_cache_txn *txn, struct kr_request *req)
{
	struct stash_baton baton = {
		.req = req,
		.qry = qry,
		.txn = txn,
		.timestamp = qry->timestamp.tv_sec,
		.min_ttl = DEFAULT_MINTTL
	};
	return map_walk(stash, &commit_rr, &baton);
}

static void stash_glue(map_t *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, mm_ctx_t *pool)
{
	const knot_pktsection_t *additional = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < additional->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(additional, i);
		if ((rr->type != KNOT_RRTYPE_A && rr->type != KNOT_RRTYPE_AAAA) ||
		    !knot_dname_is_equal(rr->owner, ns_name)) {
			continue;
		}
		kr_rrmap_add(stash, rr, KR_RANK_BAD, pool);
	}
}

/* @internal DS is special and is present only parent-side */
static void stash_ds(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
{
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		if (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_RRSIG) {
			kr_rrmap_add(stash, rr, KR_RANK_AUTH, pool);
		}
	}
}

static int stash_authority(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
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
		kr_rrmap_add(stash, rr, KR_RANK_NONAUTH, pool);
	}
	return kr_ok();
}

static int stash_answer(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
{
	const knot_dname_t *cname = knot_pkt_qname(pkt);
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < answer->count; ++i) {
		/* Stash direct answers (equal to current QNAME/CNAME),
		 * accept out-of-order RRSIGS. */
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (!knot_dname_is_equal(rr->owner, cname)
		    && rr->type != KNOT_RRTYPE_RRSIG) {
			continue;
		}
		kr_rrmap_add(stash, rr, KR_RANK_AUTH, pool);
		/* Follow CNAME chain in current cut. */
		if (rr->type == KNOT_RRTYPE_CNAME) {
			const knot_dname_t *next_cname = knot_cname_name(&rr->rrs);
			if (knot_dname_in(qry->zone_cut.name, next_cname)) {
				cname = next_cname;
			}
		} else if (rr->type != KNOT_RRTYPE_RRSIG) {
			cname = qry->sname;
		}
	}
	return kr_ok();
}

static int stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	if (!qry || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}
	/* Do not cache truncated answers. */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}
	/* Cache only positive answers, not meta types or RRSIG. */
	const uint16_t qtype = knot_pkt_qtype(pkt);
	const bool is_eligible = !(knot_rrtype_is_metatype(qtype) || qtype == KNOT_RRTYPE_RRSIG);
	if (qry->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR || !is_eligible) {
		return ctx->state;
	}
	/* Stash in-bailiwick data from the AUTHORITY and ANSWER. */
	map_t stash = map_make();
	stash.malloc = (map_alloc_f) mm_alloc;
	stash.free = (map_free_f) mm_free;
	stash.baton = &req->pool;
	int ret = 0;
	bool is_auth = knot_wire_get_aa(pkt->wire);
	if (is_auth) {
		ret = stash_answer(qry, pkt, &stash, &req->pool);
	}
	/* Cache authority only if chasing referral/cname chain */
	if (!is_auth || qry != TAIL(req->rplan.pending)) {
		ret = stash_authority(qry, pkt, &stash, &req->pool);
	}
	/* Cache DS records in referrals */
	if (!is_auth && knot_pkt_has_dnssec(pkt)) {
		stash_ds(qry, pkt, &stash, &req->pool);
	}
	/* Cache stashed records */
	if (ret == 0 && stash.root != NULL) {
		/* Open write transaction */
		struct kr_cache *cache = &req->ctx->cache;
		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
			ret = stash_commit(&stash, qry, &txn, req);
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
		.produce = &peek,
		.consume = &stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrcache)
