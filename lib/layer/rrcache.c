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

#include <assert.h>

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

static int loot_rr(struct kr_cache *cache, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry,
                  uint8_t *rank, uint8_t *flags, bool fetch_rrsig)
{
	/* Check if record exists in cache */
	int ret = 0;
	uint32_t drift = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, rrtype, rrclass);
	if (fetch_rrsig) {
		ret = kr_cache_peek_rrsig(cache, &cache_rr, rank, flags, &drift);
	} else {
		ret = kr_cache_peek_rr(cache, &cache_rr, rank, flags, &drift);
	}
	if (ret != 0) {
		return ret;
	}

	/* Mark as expiring if it has less than 1% TTL (or less than 5s) */
	if (is_expiring(&cache_rr, drift)) {
		qry->flags |= QUERY_EXPIRING;
	}

	assert(flags != NULL);
	if ((*flags) & KR_CACHE_FLAG_WCARD_PROOF) {
		/* Record was found, but wildcard answer proof is needed.
		 * Do not update packet, try to fetch whole packet from pktcache instead. */
		qry->flags |= QUERY_DNSSEC_WEXPAND;
		return kr_error(ENOENT);
	}

	/* Update packet question */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)) {
		kr_pkt_recycle(pkt);
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
static int loot_rrcache(struct kr_cache *cache, knot_pkt_t *pkt, struct kr_query *qry, uint16_t rrtype, bool dobit)
{
	/* Lookup direct match first */
	uint8_t rank  = 0;
	uint8_t flags = 0;
	int ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, &flags, 0);
	if (ret != 0 && rrtype != KNOT_RRTYPE_CNAME) { /* Chase CNAME if no direct hit */
		rrtype = KNOT_RRTYPE_CNAME;
		ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, &flags, 0);
	}
	/* Record is flagged as INSECURE => doesn't have RRSIG. */
	if (ret == 0 && (rank & KR_RANK_INSECURE)) {
		qry->flags |= QUERY_DNSSEC_INSECURE;
		qry->flags &= ~QUERY_DNSSEC_WANT;
	/* Record may have RRSIG, try to find it. */
	} else if (ret == 0 && dobit) {
		ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry, &rank, &flags, true);
	}
	return ret;
}

static int rrcache_peek(knot_layer_t *ctx, knot_pkt_t *pkt)
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
		ret = loot_rrcache(cache, pkt, qry, qry->stype, (qry->flags & QUERY_DNSSEC_WANT));
	} else {
		/* ANY query are used by either qmail or certain versions of Firefox.
		 * Probe cache for a few interesting records. */
		static uint16_t any_types[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA, KNOT_RRTYPE_MX };
		for (size_t i = 0; i < sizeof(any_types)/sizeof(any_types[0]); ++i) {
			if (loot_rrcache(cache, pkt, qry, any_types[i], (qry->flags & QUERY_DNSSEC_WANT)) == 0) {
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
struct rrcache_baton
{
	struct kr_request *req;
	struct kr_query *qry;
	struct kr_cache *cache;
	unsigned timestamp;
	uint32_t min_ttl;
};

static int commit_rrsig(struct rrcache_baton *baton, uint8_t rank, uint8_t flags, knot_rrset_t *rr)
{
	/* If not doing secure resolution, ignore (unvalidated) RRSIGs. */
	if (!(baton->qry->flags & QUERY_DNSSEC_WANT)) {
		return kr_ok();
	}
	/* Commit covering RRSIG to a separate cache namespace. */
	return kr_cache_insert_rrsig(baton->cache, rr, rank, flags, baton->timestamp);
}

static int commit_rr(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct rrcache_baton *baton = data;
	/* Ensure minimum TTL */
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) < baton->min_ttl) {
			knot_rdata_set_ttl(rd, baton->min_ttl);
		}
		rd = kr_rdataset_next(rd);
	}

	/* Save RRSIG in a special cache. */
	uint8_t rank = KEY_FLAG_RANK(key);
	/* Non-authoritative NSs should never be trusted,
	 * it may be present in an otherwise secure answer but it
	 * is only a hint for local state. */
	if (rr->type != KNOT_RRTYPE_NS || (rank & KR_RANK_AUTH)) {
	 	if (baton->qry->flags & QUERY_DNSSEC_WANT)
			rank |= KR_RANK_SECURE;
	}
	if (baton->qry->flags & QUERY_DNSSEC_INSECURE) {
		rank |= KR_RANK_INSECURE;
	}
	if (KEY_COVERING_RRSIG(key)) {
		return commit_rrsig(baton, rank, KR_CACHE_FLAG_NONE, rr);
	}
	/* Accept only better rank (if not overriding) */
	if (!(rank & KR_RANK_SECURE) && !(baton->qry->flags & QUERY_NO_CACHE)) {
		int cached_rank = kr_cache_peek_rank(baton->cache, KR_CACHE_RR, rr->owner, rr->type, baton->timestamp);
		if (cached_rank >= rank) {
			return kr_ok();
		}
	}

	uint8_t flags = KR_CACHE_FLAG_NONE;
	if ((rank & KR_RANK_AUTH) && (baton->qry->flags & QUERY_DNSSEC_WEXPAND)) {
		flags |= KR_CACHE_FLAG_WCARD_PROOF;
	}
	return kr_cache_insert_rr(baton->cache, rr, rank, flags, baton->timestamp);
}

static int stash_commit(map_t *stash, struct kr_query *qry, struct kr_cache *cache, struct kr_request *req)
{
	struct rrcache_baton baton = {
		.req = req,
		.qry = qry,
		.cache = cache,
		.timestamp = qry->timestamp.tv_sec,
		.min_ttl = DEFAULT_MINTTL
	};
	return map_walk(stash, &commit_rr, &baton);
}

static void stash_glue(map_t *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, knot_mm_t *pool)
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
static void stash_ds(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
{
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		if (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_RRSIG) {
			kr_rrmap_add(stash, rr, KR_RANK_AUTH, pool);
		}
	}
}

static int stash_authority(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
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
			const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, 0);
			if (qry->flags & QUERY_PERMISSIVE || knot_dname_in(qry->zone_cut.name, ns_name)) {
				stash_glue(stash, pkt, ns_name, pool);
			}
		}
		/* Stash record */
		kr_rrmap_add(stash, rr, KR_RANK_NONAUTH, pool);
	}
	return kr_ok();
}

static int stash_answer(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
{
	/* Work with QNAME, as minimised name data is cacheable. */
	const knot_dname_t *cname_begin = knot_pkt_qname(pkt);
	if (!cname_begin) {
		cname_begin = qry->sname;
	}
	const knot_dname_t *cname = cname_begin;
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
		/* Follow CNAME chain in current cut (if SECURE). */
		if ((qry->flags & QUERY_DNSSEC_WANT) && rr->type == KNOT_RRTYPE_CNAME) {
			const knot_dname_t *next_cname = knot_cname_name(&rr->rrs);
			if (next_cname && knot_dname_in(qry->zone_cut.name, next_cname)) {
				cname = next_cname;
			}
		} else if (rr->type != KNOT_RRTYPE_RRSIG) {
			cname = cname_begin;
		}
	}
	return kr_ok();
}

static int rrcache_stash(knot_layer_t *ctx, knot_pkt_t *pkt)
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
		if (ret == 0) {
			ret = stash_authority(qry, pkt, &stash, &req->pool);
		}
	/* Cache authority only if chasing referral/cname chain */
	} else if (!is_auth || qry != array_tail(req->rplan.pending)) {
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
		ret = stash_commit(&stash, qry, cache, req);
		/* Clear if full */
		if (ret == kr_error(ENOSPC)) {
			ret = kr_cache_clear(cache);
			if (ret != 0) {
				kr_log_error("[cache] failed to clear cache: %s\n", kr_strerror(ret));
			}
		}
		kr_cache_sync(cache);
	}
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *rrcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.produce = &rrcache_peek,
		.consume = &rrcache_stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrcache)

#undef DEBUG_MSG
