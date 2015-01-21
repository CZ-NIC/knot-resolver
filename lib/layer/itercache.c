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

static int read_cache_append(knot_pkt_t *answer, namedb_txn_t *txn, knot_rrset_t *cache_rr, uint32_t timestamp)
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

static int read_cache_zonecut(struct kr_zonecut *cut, namedb_txn_t *txn, knot_rrset_t *cache_rr, uint32_t timestamp)
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

static int read_cache(knot_layer_t *ctx, knot_pkt_t *pkt)
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
		ret = read_cache_zonecut(&cur->zone_cut, txn, &cache_rr, timestamp);
		if (ret == KNOT_EOK) {
			kr_rplan_pop(param->rplan, cur);
			return KNOT_NS_PROC_DONE;
		}

		return ctx->state;
	}

	/* Try to find a CNAME/DNAME chain first. */
	cache_rr.type = KNOT_RRTYPE_CNAME;
	ret = read_cache_append(param->answer, txn, &cache_rr, timestamp);
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
	ret = read_cache_append(param->answer, txn, &cache_rr, timestamp);
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

	if (cache_rr->rrs.rr_count == 0) {
		return KNOT_ENOENT;
	}
	return ret;
}

/*! \brief Cache direct answer. */
static int write_cache_rr(const knot_pktsection_t *section, knot_rrset_t *rr, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	/* Cache CNAME chain. */
	int ret = KNOT_EOK;
	uint16_t orig_rrtype = rr->type;
	rr->type = KNOT_RRTYPE_CNAME;
	while((merge_in_section(rr, section, 0, pool)) == KNOT_EOK) {
		/* Cache the merged RRSet */
		ret = kr_cache_insert(txn, rr, timestamp);
		if (ret != KNOT_EOK) {
			return ret;
		}
		/* Follow the chain */
		rr->owner = (knot_dname_t *)knot_ns_name(&rr->rrs, 0);
		knot_rdataset_clear(&rr->rrs, pool);

	}

	/* Now there may be a terminal record. */
	rr->type = orig_rrtype;
	ret = merge_in_section(rr, section, 0, pool);
	if (ret == KNOT_EOK) {
		kr_cache_insert(txn, rr, timestamp);
		knot_rdataset_clear(&rr->rrs, pool);
	}

	return ret;
}

/*! \brief Cache direct answer. */
static int write_cache_answer(knot_pkt_t *pkt, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)knot_pkt_qname(pkt), knot_pkt_qtype(pkt), knot_pkt_qclass(pkt));

	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	return write_cache_rr(an, &cache_rr, txn, pool, timestamp);
}

/*! \brief Cache stub nameservers. */
static int write_cache_authority(knot_pkt_t *pkt, namedb_txn_t *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	knot_rrset_t glue_rr = { NULL, 0, 0 };
	knot_rrset_t cache_rr = { NULL, 0, 0 };
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	static const uint16_t type_list[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA };

	/* Scan for NS records, cache glue. */
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			/* Cache glue (if contains) */
			for (unsigned i = 0; i < sizeof(type_list)/sizeof(uint16_t); ++i) {
				knot_dname_t *owner = (knot_dname_t *)knot_ns_name(&rr->rrs, 0);
				knot_rrset_init(&glue_rr, owner, type_list[i], rr->rclass);
				(void) write_cache_rr(ar, &glue_rr, txn, pool, timestamp);
			}
			/* Keep first NS */
			if (cache_rr.owner == NULL) {
				knot_rrset_init(&cache_rr, (knot_dname_t *)rr->owner, rr->type, rr->rclass);
			}
		}
	}

	/* Merge and cache NS record. */
	if (cache_rr.owner == NULL) {
		return KNOT_ENOENT;
	}

	return write_cache_rr(ns, &cache_rr, txn, pool, timestamp);
}

static int write_cache(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_layer_param *param = ctx->data;
	struct kr_query *last_query = kr_rplan_last(param->rplan);

	/* Don't cache anything if failed / no query. */
	if (ctx->state == KNOT_NS_PROC_FAIL || last_query == NULL) {
		return ctx->state;
	}

	/* Open write transaction */
	mm_ctx_t *pool = param->rplan->pool;
	uint32_t timestamp = last_query->timestamp.tv_sec;
	namedb_txn_t *txn = kr_rplan_txn_acquire(param->rplan, 0);
	if (txn == NULL) {
		return ctx->state; /* Couldn't acquire cache, ignore. */
	}

	/* Cache only positive answers. */
	/*! \todo Negative answers cache support */
	if (knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return ctx->state;
	}

	/* If authoritative, cache answer for current query. */
	int ret = KNOT_EOK;
	if (knot_wire_get_aa(pkt->wire)) {
		ret = write_cache_answer(pkt, txn, pool, timestamp);
	} else {
		ret = write_cache_authority(pkt, txn, pool, timestamp);
	}

	/* Cache full, do what we must. */
	if (ret == KNOT_ESPACE) {
		kr_cache_clear(txn);
	}

	return ctx->state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_ITERCACHE_MODULE = {
        &begin,
        NULL,
        NULL,
        &write_cache,
        &read_cache,
        NULL
};

const knot_layer_api_t *layer_itercache_module(void)
{
	return &LAYER_ITERCACHE_MODULE;
}
