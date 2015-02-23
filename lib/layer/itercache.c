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

#include "lib/layer/iterate.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(param->rplan), " cc ",  fmt)

typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_layer_param *);

static int update_parent(const knot_rrset_t *rr, unsigned drift, struct kr_layer_param *param)
{
	/* Find a first non-expired record. */
	uint16_t i = 0;
	for (; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdata_ttl(rd) > drift) {
			break;
		}
	}

	return rr_update_parent(rr, i, param);
}

static int update_answer(const knot_rrset_t *rr, unsigned drift, struct kr_layer_param *param)
{
	knot_pkt_t *answer = param->answer;

	/* Materialize RR set */
	knot_rrset_t rr_copy = kr_cache_materialize(rr, drift, &answer->mm);
	if (rr_copy.rrs.rr_count == 0) {
		return KNOT_NS_PROC_FAIL;
	}
	
	return rr_update_answer(&rr_copy, 0, param);
}

static int read_cache_rr(namedb_txn_t *txn, knot_rrset_t *cache_rr, uint32_t timestamp,
                         rr_callback_t cb, struct kr_layer_param *param)
{
	/* Query cache for requested record */
	if (kr_cache_peek(txn, cache_rr, &timestamp) != KNOT_EOK) {
		return KNOT_NS_PROC_NOOP;
	}

	return cb(cache_rr, timestamp, param);
}

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int read_cache(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_query *cur = kr_rplan_current(param->rplan);
	if (cur == NULL) {
		return ctx->state;
	}

	namedb_txn_t *txn = kr_rplan_txn_acquire(param->rplan, NAMEDB_RDONLY);
	uint32_t timestamp = cur->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, cur->sname, cur->stype, cur->sclass);

	/* Check if updating parent zone cut. */
	rr_callback_t callback = &update_parent;
	if (cur->parent == NULL) {
		callback = &update_answer;
	}

	/* Try to find expected record first. */
	int state = read_cache_rr(txn, &cache_rr, timestamp, callback, param);
	if (state == KNOT_NS_PROC_DONE) {
		DEBUG_MSG("=> satisfied from cache\n");
		kr_rplan_pop(param->rplan, cur);
		return state;
	}

	/* Check if CNAME chain exists. */
	cache_rr.type = KNOT_RRTYPE_CNAME;
	state = read_cache_rr(txn, &cache_rr, timestamp, callback, param);
	if (state != KNOT_NS_PROC_NOOP) {
		if (cur->stype != KNOT_RRTYPE_CNAME) {
			const knot_dname_t *cname = knot_cname_name(&cache_rr.rrs);
			if (kr_rplan_push(param->rplan, cur->parent, cname, cur->sclass, cur->stype) == NULL) {
				return KNOT_NS_PROC_FAIL;
			}
		}

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
	/* Check if already cached. */
	knot_rrset_t query_rr;
	knot_rrset_init(&query_rr, rr->owner, rr->type, rr->rclass);
	if (kr_cache_peek(txn, &query_rr, &timestamp) == KNOT_EOK) {
		return KNOT_EOK;
	}

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
	struct kr_query *query = kr_rplan_current(param->rplan);

	/* Don't cache anything if failed. */
	if (query == NULL || ctx->state == KNOT_NS_PROC_FAIL) {
		return ctx->state;
	}

	/* Open write transaction */
	mm_ctx_t *pool = param->rplan->pool;
	uint32_t timestamp = query->timestamp.tv_sec;
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
	}

	ret = write_cache_authority(pkt, txn, pool, timestamp);

	/* Cache full, do what we must. */
	if (ret == KNOT_ESPACE) {
		kr_cache_clear(txn);
	}

	return ctx->state;
}

/*! \brief Module implementation. */
const knot_layer_api_t *itercache_layer(void)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.in = &write_cache,
		.out = &read_cache
	};

	return &_layer;
}
