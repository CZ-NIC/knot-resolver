/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <libknot/rrset.h>
#include <libknot/rrtype/soa.h>

#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/module.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG((qry), " pc ",  fmt)
#define DEFAULT_MAXTTL (15 * 60)
#define DEFAULT_NOTTL (5) /* Short-time "no data" retention to avoid bursts */

static uint32_t limit_ttl(uint32_t ttl)
{
	/* @todo Configurable limit */
	return (ttl > DEFAULT_MAXTTL) ? DEFAULT_MAXTTL : ttl;
}

static void adjust_ttl(knot_rrset_t *rr, uint32_t drift)
{
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		uint32_t ttl = knot_rdata_ttl(rd);
		if (ttl >= drift) {
			knot_rdata_set_ttl(rd, ttl - drift);
		}
		rd = kr_rdataset_next(rd);
	}
}

static int loot_cache_pkt(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t rrtype, bool want_secure, uint32_t timestamp)
{
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(txn, KR_CACHE_PKT, qname, rrtype, &entry, &timestamp);
	if (ret != 0) { /* Not in the cache */
		return ret;
	}

	/* Check that we have secure rank. */
	if (want_secure && entry->rank == KR_RANK_BAD) {
		return kr_error(ENOENT);
	}

	/* Copy answer, keep the original message id */
	if (entry->count <= pkt->max_size) {
		/* Keep original header and copy cached */
		uint16_t msgid = knot_wire_get_id(pkt->wire);
		/* Copy and reparse */
		knot_pkt_clear(pkt);
		memcpy(pkt->wire, entry->data, entry->count);
		pkt->size = entry->count;
		knot_pkt_parse(pkt, 0);
		/* Restore header bits */
		knot_wire_set_id(pkt->wire, msgid);
	}

	/* Adjust TTL in records. */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			adjust_ttl((knot_rrset_t *)rr, timestamp);
		}
	}

	return ret;
}

/** @internal Try to find a shortcut directly to searched packet. */
static int loot_pktcache(struct kr_cache_txn *txn, knot_pkt_t *pkt, struct kr_query *qry)
{
	uint32_t timestamp = qry->timestamp.tv_sec;
	const knot_dname_t *qname = qry->sname;
	uint16_t rrtype = qry->stype;
	const bool want_secure = (qry->flags & QUERY_DNSSEC_WANT);
	return loot_cache_pkt(txn, pkt, qname, rrtype, want_secure, timestamp);
}

static int pktcache_peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE) || (qry->flags & QUERY_NO_CACHE)) {
		return ctx->state; /* Already resolved/failed */
	}
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC) {
		return ctx->state; /* Only lookup before asking a query */
	}
	if (knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state; /* Only IN class */
	}

	/* Prepare read transaction */
	struct kr_cache_txn txn;
	struct kr_cache *cache = &req->ctx->cache;
	if (kr_cache_txn_begin(cache, &txn, KNOT_DB_RDONLY) != 0) {
		return ctx->state;
	}

	/* Fetch either answer to original or minimized query */
	int ret = loot_pktcache(&txn, pkt, qry);
	kr_cache_txn_abort(&txn);
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

static uint32_t packet_ttl(knot_pkt_t *pkt)
{
	bool has_ttl = false;
	uint32_t ttl = UINT32_MAX;
	/* Get minimum entry TTL in the packet */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			/* Skip OPT and TSIG */
			if (rr->type == KNOT_RRTYPE_OPT || rr->type == KNOT_RRTYPE_TSIG) {
				continue;
			}
			knot_rdata_t *rd = rr->rrs.data;
			for (uint16_t j = 0; j < rr->rrs.rr_count; ++j) {
				if (knot_rdata_ttl(rd) < ttl) {
					ttl = knot_rdata_ttl(rd);
					has_ttl = true;
				}
				rd = kr_rdataset_next(rd);
			}
		}
	}
	/* Get default if no valid TTL present */
	if (!has_ttl) {
		ttl = DEFAULT_NOTTL;
	}
	return limit_ttl(ttl);
}

static int pktcache_stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	/* Cache only answers that make query resolved (i.e. authoritative)
	 * that didn't fail during processing and are negative. */
	if (qry->flags & QUERY_CACHED || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state; /* Don't cache anything if failed. */
	}
	/* Cache only authoritative answers from IN class. */
	if (!knot_wire_get_aa(pkt->wire) || knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Cache only NODATA/NXDOMAIN or metatype/RRSIG or
         * wildcard expanded answers. */
	const uint16_t qtype = knot_pkt_qtype(pkt);
	const bool is_eligible = (knot_rrtype_is_metatype(qtype) ||
				  qtype == KNOT_RRTYPE_RRSIG);
	int pkt_class = kr_response_classify(pkt);
	if (!(is_eligible || (pkt_class & (PKT_NODATA|PKT_NXDOMAIN)) ||
	    (qry->flags & QUERY_DNSSEC_WEXPAND))) {
		return ctx->state;
	}
	uint32_t ttl = packet_ttl(pkt);
	if (ttl == 0) {
		return ctx->state; /* No useable TTL, can't cache this. */
	}
	const knot_dname_t *qname = knot_pkt_qname(pkt);
	if (!qname) {
		return ctx->state;
	}
	/* Open write transaction and prepare answer */
	struct kr_cache_txn txn;
	if (kr_cache_txn_begin(&req->ctx->cache, &txn, 0) != 0) {
		return ctx->state; /* Couldn't acquire cache, ignore. */
	}
	knot_db_val_t data = { pkt->wire, pkt->size };
	struct kr_cache_entry header = {
		.timestamp = qry->timestamp.tv_sec,
		.ttl = ttl,
		.rank = KR_RANK_BAD,
		.count = data.len
	};

	/* Set cache rank */
	if (qry->flags & QUERY_DNSSEC_WANT) {
		header.rank = KR_RANK_SECURE;
	} else if (qry->flags & QUERY_DNSSEC_INSECURE) {
		header.rank = KR_RANK_INSECURE;
	}

	/* Check if we can replace (allow current or better rank, SECURE is always accepted). */
	if (header.rank < KR_RANK_SECURE) {
		int cached_rank = kr_cache_peek_rank(&txn, KR_CACHE_PKT, qname, qtype, header.timestamp);
		if (cached_rank > header.rank) {
			kr_cache_txn_abort(&txn);
			return ctx->state;
		}
	}

	/* Stash answer in the cache */
	int ret = kr_cache_insert(&txn, KR_CACHE_PKT, qname, qtype, &header, data);	
	if (ret != 0) {
		kr_cache_txn_abort(&txn);
	} else {
		DEBUG_MSG(qry, "=> answer cached for TTL=%u\n", ttl);
		kr_cache_txn_commit(&txn);
	}
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *pktcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.produce = &pktcache_peek,
		.consume = &pktcache_stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(pktcache)

#undef DEBUG_MSG
