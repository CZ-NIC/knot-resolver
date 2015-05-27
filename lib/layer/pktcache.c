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

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), " pc ",  fmt)
#define DEFAULT_MAXTTL (15 * 60)
#define DEFAULT_NOTTL (5) /* Short-time "no data" retention to avoid bursts */

static inline uint8_t get_tag(knot_pkt_t *pkt)
{
	return knot_pkt_has_dnssec(pkt) ? KR_CACHE_SEC : KR_CACHE_PKT;
}

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static uint32_t limit_ttl(uint32_t ttl)
{
	/* @todo Configurable limit */
	return (ttl > DEFAULT_MAXTTL) ? DEFAULT_MAXTTL : ttl;
}

static void adjust_ttl(knot_rrset_t *rr, uint32_t drift)
{
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		uint32_t ttl = knot_rdata_ttl(rd);
		if (ttl >= drift) {
			knot_rdata_set_ttl(rd, ttl - drift);
		}
	}
}

static int loot_cache_pkt(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t rrtype, uint8_t tag, uint32_t timestamp)
{
	struct kr_cache_entry *entry;
	entry = kr_cache_peek(txn, tag, qname, rrtype, &timestamp);
	if (!entry) { /* Not in the cache */
		return kr_error(ENOENT);
	}

	/* Copy answer, keep the original message id */
	if (entry->count <= pkt->max_size) {
		/* Keep original header and copy cached */
		uint8_t header[KNOT_WIRE_HEADER_SIZE];
		memcpy(header, pkt->wire, sizeof(header));
		/* Copy and reparse */
		knot_pkt_clear(pkt);
		memcpy(pkt->wire, entry->data, entry->count);
		pkt->size = entry->count;
		knot_pkt_parse(pkt, 0);
		/* Restore header bits */
		knot_wire_set_id(pkt->wire, knot_wire_get_id(header));
	}

	/* Adjust TTL in records. */
	int ret = 0;
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
static int loot_cache(struct kr_cache_txn *txn, knot_pkt_t *pkt, uint8_t tag, struct kr_query *qry)
{
	uint32_t timestamp = qry->timestamp.tv_sec;
	const knot_dname_t *qname = qry->sname;
	uint16_t rrtype = qry->stype;
	return loot_cache_pkt(txn, pkt, qname, rrtype, tag, timestamp);
}

static int peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}
	if (knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state; /* Only IN class */
	}

	/* Prepare read transaction */
	struct kr_cache_txn txn;
	struct kr_cache *cache = &req->ctx->cache;
	if (kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY) != 0) {
		return ctx->state;
	}

	/* Fetch either answer to original or minimized query */
	uint8_t tag = get_tag(req->answer);
	int ret = loot_cache(&txn, pkt, tag, qry);
	kr_cache_txn_abort(&txn);
	if (ret == 0) {
		DEBUG_MSG("=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		return KNOT_STATE_DONE;
	}
	return ctx->state;
}

static uint32_t packet_ttl(knot_pkt_t *pkt)
{
	uint32_t ttl = DEFAULT_NOTTL;
	/* Fetch SOA from authority. */
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_SOA) {
			ttl = knot_soa_minimum(&rr->rrs);
			break;
		}
	}
	/* Get minimum entry TTL in the packet */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			/* Skip OPT and TSIG */
			if (rr->type == KNOT_RRTYPE_OPT || rr->type == KNOT_RRTYPE_TSIG) {
				continue;
			}
			for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
				knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
				if (knot_rdata_ttl(rd) < ttl) {
					ttl = knot_rdata_ttl(rd);
				}
			}
		}
	}
	return limit_ttl(ttl);
}

static int stash(knot_layer_t *ctx)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	if (EMPTY_LIST(rplan->resolved) || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state; /* Don't cache anything if failed. */
	}
	struct kr_query *qry = TAIL(rplan->resolved);
	knot_pkt_t *pkt = req->answer;
	if (knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state; /* Only IN class */
	}
	int pkt_class = kr_response_classify(pkt);
	if (qry->flags & QUERY_CACHED || !(pkt_class & (PKT_NODATA|PKT_NXDOMAIN))) {
		return ctx->state; /* Cache only negative, not-cached answers. */
	}
	uint32_t ttl = packet_ttl(pkt);
	if (ttl == 0) {
		return ctx->state; /* No useable TTL, can't cache this. */
	}

	/* Open write transaction and prepare answer */
	struct kr_cache_txn txn;
	if (kr_cache_txn_begin(&req->ctx->cache, &txn, 0) != 0) {
		return ctx->state; /* Couldn't acquire cache, ignore. */
	}
	const knot_dname_t *qname = knot_pkt_qname(pkt);
	uint16_t qtype = knot_pkt_qtype(pkt);
	namedb_val_t data = { pkt->wire, pkt->size };
	struct kr_cache_entry header = {
		.timestamp = qry->timestamp.tv_sec,
		.ttl = ttl,
		.count = data.len
	};

	/* Stash answer in the cache */
	int ret = kr_cache_insert(&txn, get_tag(pkt), qname, qtype, &header, data);	
	if (ret == KNOT_ESPACE) {
		kr_cache_txn_abort(&txn);
	} else {
		DEBUG_MSG("=> answer cached for TTL=%u\n", ttl);
		kr_cache_txn_commit(&txn);
	}
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *pktcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin   = &begin,
		.produce = &peek,
		.finish  = &stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(pktcache)