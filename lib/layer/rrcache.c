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
#include "lib/cache.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), " rc ",  fmt)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int loot_rr(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry)
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
		uint8_t header[KNOT_WIRE_HEADER_SIZE];
		memcpy(header, pkt->wire, sizeof(header));
		knot_pkt_clear(pkt);
		memcpy(pkt->wire, header, sizeof(header));
		knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
	}

	/* Update packet answer */
	knot_rrset_t rr_copy = kr_cache_materialize(&cache_rr, timestamp, &pkt->mm);
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &rr_copy, KNOT_PF_FREE);
	if (ret != 0) {
		knot_rrset_clear(&rr_copy, &pkt->mm);
		return ret;
	}
	return kr_ok();
}

static int loot_cache_set(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t rrclass, uint16_t rrtype, struct kr_query *qry)
{
	int ret = loot_rr(txn, pkt, qname, rrclass, rrtype, qry);
	if (ret == kr_error(ENOENT) && rrtype != KNOT_RRTYPE_CNAME) { /* Chase CNAME if no direct hit */
		ret = loot_rr(txn, pkt, qname, rrclass, KNOT_RRTYPE_CNAME, qry);
	}
	return ret;
}

/** @internal Try to find a shortcut directly to searched record, otherwise try to find minimised QNAME. */
static int loot_cache(struct kr_cache_txn *txn, knot_pkt_t *pkt, struct kr_query *qry)
{
	const knot_dname_t *qname = qry->sname;
	uint16_t rrclass = qry->sclass;
	uint16_t rrtype = qry->stype;
	int ret = loot_cache_set(txn, pkt, qname, rrclass, rrtype, qry);
	if (ret == 0) { /* Signalize minimisation disabled */
		qry->flags |= QUERY_NO_MINIMIZE;
	} else { /* Retry with minimised name */
		qname = knot_pkt_qname(pkt);
		rrtype = knot_pkt_qtype(pkt);
		if (!knot_dname_is_equal(qname, qry->sname)) {
			ret = loot_cache_set(txn, pkt, qname, rrclass, rrtype, qry);
		}
	}
	return ret;
}

static int peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE)) {
		return ctx->state;
	}

	struct kr_cache_txn txn;
	struct kr_cache *cache = &req->ctx->cache;
	if (kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY) != 0) {
		return ctx->state;
	}

	/* Reconstruct the answer from the cache,
	 * it may either be a CNAME chain or direct answer.
	 * Only one step of the chain is resolved at a time.
	 */
	int ret = loot_cache(&txn, pkt, qry);
	kr_cache_txn_abort(&txn);
	if (ret == 0) {
		DEBUG_MSG("=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KNOT_STATE_DONE;
	}
	return ctx->state;
}

/** Merge-in record if same type and owner. */
static int merge_cache_rr(knot_rrset_t *cache_rr, const knot_rrset_t *rr, mm_ctx_t *pool)
{
	if (rr->type != cache_rr->type || !knot_dname_is_equal(rr->owner, cache_rr->owner)) {
		return KNOT_EOK; /* Ignore */
	}

	return knot_rdataset_merge(&cache_rr->rrs, &rr->rrs, pool);
}

/** Merge-in records from the same section. */
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

/** Cache direct answer. */
static int write_cache_rr(const knot_pktsection_t *section, knot_rrset_t *rr, struct kr_cache_txn *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	/* Check if already cached. */
	knot_rrset_t query_rr;
	knot_rrset_init(&query_rr, rr->owner, rr->type, rr->rclass);
	if (kr_cache_peek_rr(txn, &query_rr, &timestamp) == KNOT_EOK) {
		return KNOT_EOK;
	}

	/* Cache CNAME chain. */
	int ret = KNOT_EOK;
	uint16_t orig_rrtype = rr->type;
	rr->type = KNOT_RRTYPE_CNAME;
	while((merge_in_section(rr, section, 0, pool)) == KNOT_EOK) {
		/* Cache the merged RRSet */
		ret = kr_cache_insert_rr(txn, rr, timestamp);
		if (ret != KNOT_EOK) {
			return ret;
		}
		/* Follow the chain */
		rr->owner = (knot_dname_t *)knot_ns_name(&rr->rrs, 0);
		knot_rdataset_clear(&rr->rrs, pool);
		/* Check if target already cached. */
		if (kr_cache_peek_rr(txn, rr, &timestamp) == KNOT_EOK) {
			break;
		}
	}

	/* Now there may be a terminal record. */
	rr->type = orig_rrtype;
	ret = merge_in_section(rr, section, 0, pool);
	if (ret == KNOT_EOK) {
		kr_cache_insert_rr(txn, rr, timestamp);
		knot_rdataset_clear(&rr->rrs, pool);
	}

	return ret;
}

/** Cache direct answer. */
static int write_cache_answer(knot_pkt_t *pkt, struct kr_cache_txn *txn, mm_ctx_t *pool, uint32_t timestamp)
{
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)knot_pkt_qname(pkt), knot_pkt_qtype(pkt), knot_pkt_qclass(pkt));

	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	return write_cache_rr(an, &cache_rr, txn, pool, timestamp);
}

/** Cache stub nameservers. */
static int write_cache_authority(knot_pkt_t *pkt, struct kr_cache_txn *txn, mm_ctx_t *pool, uint32_t timestamp)
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

static int stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *query = kr_rplan_current(rplan);
	if (!query || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Cache only positive answers. */
	if (query->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return ctx->state;
	}

	/* Open write transaction */
	mm_ctx_t *pool = rplan->pool;
	uint32_t timestamp = query->timestamp.tv_sec;
	struct kr_cache *cache = &req->ctx->cache;
	struct kr_cache_txn txn;
	if (kr_cache_txn_begin(cache, &txn, 0) != 0) {
		return ctx->state; /* Couldn't acquire cache, ignore. */
	}

	/* If authoritative, cache answer for current query. */
	int ret = KNOT_EOK;
	if (knot_wire_get_aa(pkt->wire)) {
		ret = write_cache_answer(pkt, &txn, pool, timestamp);
	}
	if (ret == KNOT_EOK) {
		ret = write_cache_authority(pkt, &txn, pool, timestamp);
	}

	/* Cache full, do what we must. */
	if (ret == KNOT_ESPACE) {
		kr_cache_clear(&txn);
		kr_cache_txn_commit(&txn);
	} else {
		kr_cache_txn_commit(&txn);
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
