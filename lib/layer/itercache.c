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
#include <libknot/internal/mempool.h>
#include <libknot/rrtype/rdname.h>

#include "lib/layer/static.h"
#include "lib/utils.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[cache] " fmt, ## __VA_ARGS__)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int query_cache_append(knot_pkt_t *answer, namedb_txn_t *txn, knot_rrset_t *cache_rr, uint32_t timestamp)
{
	unsigned drift = timestamp;

	/* Query cache and keep drift between RRSet origin and now. */
	if (kr_cache_query(txn, cache_rr, &drift) != KNOT_EOK) {
		return KNOT_ENOENT;
	}

	/* Make RRSet copy. */
	knot_rrset_t rr_copy;
	knot_rrset_init(&rr_copy, knot_dname_copy(cache_rr->owner, &answer->mm), cache_rr->type, cache_rr->rclass);
	int ret = knot_rdataset_copy(&rr_copy.rrs, &cache_rr->rrs, &answer->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr_copy, &answer->mm);
		return ret;
	}

	/* Adjust the TTL of the records. */
	for (unsigned i = 0; i < rr_copy.rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr_copy.rrs, i);
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
	}

	/* Write copied RR to the result packet. */
	ret = knot_pkt_put(answer, KNOT_COMPR_HINT_NONE, &rr_copy, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr_copy, &answer->mm);
		knot_wire_set_tc(answer->wire);
	}

	return KNOT_EOK;
}

static int query_cache_zonecut(struct kr_zonecut *cut, namedb_txn_t *txn, knot_rrset_t *cache_rr, uint32_t timestamp)
{
	/* Query cache for requested record */
	if (kr_cache_query(txn, cache_rr, &timestamp) != KNOT_EOK) {
		return KNOT_ENOENT;
	}

	switch(cache_rr->type) {
	case KNOT_RRTYPE_NS:
		return kr_find_zone_cut(cut, cache_rr->owner, txn, timestamp);
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA:
		return kr_rrset_to_addr(&cut->addr, cache_rr);
	default:
		return KNOT_ENOENT;
	}
}

static int query_cache(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_query *cur = kr_rplan_current(param->rplan);
	if (cur == NULL) {
		return ctx->state;
	}

	int ret = KNOT_EOK;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, cur->sname, cur->stype, cur->sclass);
	namedb_txn_t *txn = kr_rplan_txn_acquire(param->rplan, NAMEDB_RDONLY);
	uint32_t timestamp = cur->timestamp.tv_sec;

	/* Check if updating current zone cut. */
	if (cur != kr_rplan_last(param->rplan)) {
		ret = query_cache_zonecut(&param->rplan->zone_cut, txn, &cache_rr, timestamp);
		if (ret == KNOT_EOK) {
			kr_rplan_pop(param->rplan, cur);
			return KNOT_NS_PROC_DONE;
		}

		return ctx->state;
	}

	/* Try to find a CNAME/DNAME chain first. */
	cache_rr.type = KNOT_RRTYPE_CNAME;
	ret = query_cache_append(param->answer, txn, &cache_rr, timestamp);
	if (ret == KNOT_EOK) {
		if (cur->stype != KNOT_RRTYPE_CNAME) {
			const knot_dname_t *cname = knot_cname_name(&cache_rr.rrs);
			if (kr_rplan_push(param->rplan, cname, cur->sclass, cur->stype) == NULL) {
				return KNOT_NS_PROC_FAIL;
			}
		}
		kr_rplan_pop(param->rplan, cur);
		return KNOT_NS_PROC_DONE;
	}

	/* Try to find expected record then. */
	cache_rr.type = cur->stype;
	ret = query_cache_append(param->answer, txn, &cache_rr, timestamp);
	if (ret == KNOT_EOK) {
		kr_rplan_pop(param->rplan, cur);
		return KNOT_NS_PROC_DONE;
	}

	/* Not resolved. */
	return KNOT_NS_PROC_MORE;
}

/*! \brief Merge-in record if same type and owner. */
static int merge_cache_rr(knot_rrset_t *cache_rr, const knot_rrset_t *rr, mm_ctx_t *pool)
{
	if (rr->type != cache_rr->type || !knot_dname_is_equal(rr->owner, cache_rr->owner)) {
		return KNOT_EOK; /* Ignore */
	}

	return knot_rdataset_merge(&cache_rr->rrs, &rr->rrs, pool);
}

/*! \brief Merge-in records from the same section. */
static int merge_in_section(knot_rrset_t *cache_rr, const knot_pktsection_t *section, unsigned from, mm_ctx_t *pool)
{
	int ret = KNOT_EOK;

	for (unsigned i = from; i < section->count; ++i) {
		ret = merge_cache_rr(cache_rr, knot_pkt_rr(section, i), pool);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

/*! \brief Cache direct answer. */
static int update_cache_answer(knot_pkt_t *pkt, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
	knot_dname_to_wire(name_buf, knot_pkt_qname(pkt), sizeof(name_buf));

	/* Cache only direct answer. */
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, name_buf, KNOT_RRTYPE_CNAME, knot_pkt_qclass(pkt));
	int ret = merge_in_section(&cache_rr, an, 0, pool);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Cache CNAME chain. */
	while(cache_rr.rrs.rr_count > 0) {
		/* Cache the merged RRSet (may fail) */
		(void) kr_cache_insert(txn, &cache_rr, timestamp);
		/* Follow the chain */
		knot_dname_to_wire(name_buf, knot_ns_name(&cache_rr.rrs, 0), sizeof(name_buf));
		knot_rdataset_clear(&cache_rr.rrs, pool);
		ret = merge_in_section(&cache_rr, an, 0, pool);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Now there may be a terminal record. */
	cache_rr.type = knot_pkt_qtype(pkt);
	knot_rdataset_clear(&cache_rr.rrs, pool);
	ret = merge_in_section(&cache_rr, an, 0, pool);
	if (ret == KNOT_EOK) {
		kr_cache_insert(txn, &cache_rr, timestamp);
	}

	return ret;
}

/*! \brief Cache stub nameservers. */
static int update_cache_authority(knot_pkt_t *pkt, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	bool found_ns_rr = false;
	knot_rrset_t cache_rr;

	/* Take first NS and merge with rest. */
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			knot_rrset_init(&cache_rr, (knot_dname_t *)rr->owner, rr->type, rr->rclass);
			found_ns_rr = true;
			break;
		}
	}

	/* Not found any viable NS */
	if (!found_ns_rr) {
		return KNOT_EOK;
	}

	int ret = merge_in_section(&cache_rr, ns, 0, pool);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Cache the merged RRSet (may fail) */
	(void) kr_cache_insert(txn, &cache_rr, timestamp);

	return ret;
}

static void update_cache_pkt(knot_pkt_t *pkt, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	/* Cache only positive answers. */
	if (knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return;
	}

	/* If authoritative, cache answer for current query. */
	if (knot_wire_get_aa(pkt->wire)) {
		update_cache_answer(pkt, txn, pool, timestamp);
	} else {
		/* Cache authority records, but not glue. */
		update_cache_authority(pkt, txn, pool, timestamp);
	}
}

static int update_cache(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_query *last_query = kr_rplan_last(param->rplan);

	/* Don't cache anything if failed / no query. */
	if (ctx->state == KNOT_NS_PROC_FAIL || last_query == NULL) {
		return ctx->state;
	}

	/* Open write transaction */
	uint32_t timestamp = last_query->timestamp.tv_sec;
	namedb_txn_t *txn = kr_rplan_txn_acquire(param->rplan, 0);
	if (txn == NULL) {
		return ctx->state; /* Couldn't acquire cache, ignore. */
	}

	/* Create memory pool for merging RRSets. */
	mm_ctx_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);

	/* Selectively cache records from the packet. */
	update_cache_pkt(pkt, txn, &pool, timestamp);

	/* Cleanup. */
	mp_delete(pool.ctx);
	return ctx->state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_ITERCACHE_MODULE = {
        &begin,
        NULL,
        NULL,
        &update_cache,
        &query_cache,
        NULL
};

const knot_layer_api_t *layer_itercache_module(void)
{
	return &LAYER_ITERCACHE_MODULE;
}
