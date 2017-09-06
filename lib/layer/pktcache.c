/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/** @file pktcache.c
 *
 * This builtin module caches whole packets from/for negative answers
 * or answers where wildcard expansion has occured (.DNSSEC_WEXPAND).
 *
 * Note: it also persists some DNSSEC_* flags.
 * The ranks are stored in *(uint8_t *)rrset->additional (all are the same for one packet).
 */

#include <libknot/descriptor.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/soa.h>

#include <contrib/ucw/lib.h>
#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/dnssec/ta.h"
#include "lib/module.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE((qry), " pc ",  fmt)
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

/** @internal Try to find a shortcut directly to searched packet. */
static int loot_pktcache(struct kr_context *ctx, knot_pkt_t *pkt,
			 struct kr_request *req, uint8_t *flags)
{
	struct kr_query *qry = req->current_query;
	uint32_t timestamp = qry->timestamp.tv_sec;
	const knot_dname_t *qname = qry->sname;
	uint16_t rrtype = qry->stype;

	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(&ctx->cache, KR_CACHE_PKT, qname,
				rrtype, &entry, &timestamp);
	if (ret != 0) { /* Not in the cache */
		if (ret == kr_error(ESTALE)) {
			VERBOSE_MSG(qry, "=> only stale entry found\n")
		}
		return ret;
	}

	uint8_t lowest_rank = KR_RANK_INITIAL | KR_RANK_AUTH;
	/* There's probably little sense for NONAUTH in pktcache. */

	if (!knot_wire_get_cd(req->answer->wire) && !(qry->flags.STUB)) {
		/* Records not present under any TA don't have their security verified at all. */
		bool ta_covers = kr_ta_covers_qry(ctx, qry->sname, qry->stype);
		/* ^ TODO: performance? */
		if (ta_covers) {
			kr_rank_set(&lowest_rank, KR_RANK_INSECURE);
		}
	}
	const bool rank_enough = entry->rank >= lowest_rank;
	VERBOSE_MSG(qry, "=> rank: 0%0.2o, lowest 0%0.2o -> satisfied=%d\n",
			entry->rank, lowest_rank, (int)rank_enough);
	if (!rank_enough) {
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

	/* Rank-related fixups.  Add rank into the additional field. */
	if (kr_rank_test(entry->rank, KR_RANK_INSECURE)) {
		qry->flags.DNSSEC_INSECURE = true;
		qry->flags.DNSSEC_WANT = false;
	}
	for (size_t i = 0; i < pkt->rrset_count; ++i) {
		assert(!pkt->rr[i].additional);
		uint8_t *rr_rank = mm_alloc(&pkt->mm, sizeof(*rr_rank));
		if (!rr_rank) {
			return kr_error(ENOMEM);
		}
		*rr_rank = entry->rank;
		pkt->rr[i].additional = rr_rank;
	}

	/* Adjust TTL in records. */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			adjust_ttl((knot_rrset_t *)rr, timestamp);
		}
	}

	/* Copy cache entry flags */
	if (flags) {
		*flags = entry->flags;
	}

	return ret;
}

static int pktcache_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) ||
	    (qry->flags.NO_CACHE)) {
		return ctx->state; /* Already resolved/failed */
	}
	/* Both caches only peek for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * Note: it's important to skip this if rrcache sets KR_STATE_DONE,
	 * as CNAME chains need more iterations to get fetched. */
	qry->flags.NO_CACHE = true;

	if (knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state; /* Only IN class */
	}

	/* Fetch either answer to original or minimized query */
	uint8_t flags = 0;
	int ret = loot_pktcache(req->ctx, pkt, req, &flags);
	kr_cache_sync(&req->ctx->cache);
	if (ret == 0) {
		qry->flags.CACHED = true;
		qry->flags.NO_MINIMIZE = true;
		if (flags & KR_CACHE_FLAG_WCARD_PROOF) {
			qry->flags.DNSSEC_WEXPAND = true;
		}
		if (flags & KR_CACHE_FLAG_OPTOUT) {
			qry->flags.DNSSEC_OPTOUT = true;
		}
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KR_STATE_DONE;
	}
	return ctx->state;
}

static uint32_t packet_ttl(knot_pkt_t *pkt, bool is_negative)
{
	bool has_ttl = false;
	uint32_t ttl = UINT32_MAX;
	/* Find minimum entry TTL in the packet or SOA minimum TTL. */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (is_negative) {
				/* Use SOA minimum TTL for negative answers. */
				if (rr->type == KNOT_RRTYPE_SOA) {
					return limit_ttl(MIN(knot_rrset_ttl(rr), knot_soa_minimum(&rr->rrs)));
				} else {
					continue; /* Use SOA only for negative answers. */
				}
			}
			if (knot_rrtype_is_metatype(rr->type)) {
				continue; /* Skip metatypes. */
			}
			/* Find minimum TTL in the record set */
			knot_rdata_t *rd = rr->rrs.data;
			for (uint16_t j = 0; j < rr->rrs.rr_count; ++j) {
				if (knot_rdata_ttl(rd) < ttl) {
					ttl = limit_ttl(knot_rdata_ttl(rd));
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

static int pktcache_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	/* Cache only answers that make query resolved (i.e. authoritative)
	 * that didn't fail during processing and are negative. */
	if (qry->flags.CACHED || ctx->state & KR_STATE_FAIL) {
		return ctx->state; /* Don't cache anything if failed. */
	}
	/* Cache only authoritative answers from IN class. */
	if (!knot_wire_get_aa(pkt->wire) || knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Cache only NODATA/NXDOMAIN or metatype/RRSIG or wildcard expanded answers. */
	const uint16_t qtype = knot_pkt_qtype(pkt);
	const bool is_eligible = (knot_rrtype_is_metatype(qtype) || qtype == KNOT_RRTYPE_RRSIG);
	bool is_negative = kr_response_classify(pkt) & (PKT_NODATA|PKT_NXDOMAIN);
	bool wcard_expansion = (qry->flags.DNSSEC_WEXPAND);
	if (is_negative && qry->flags.FORWARD && qry->flags.CNAME) {
		/* Don't cache CNAME'ed NXDOMAIN answer in forwarding mode
		   since it can contain records
		   which have not been validated by validator */
		return ctx->state;
	}
	if (!(is_eligible || is_negative || wcard_expansion)) {
		return ctx->state;
	}
	uint32_t ttl = packet_ttl(pkt, is_negative);
	if (ttl == 0) {
		return ctx->state; /* No useable TTL, can't cache this. */
	}
	const knot_dname_t *qname = knot_pkt_qname(pkt);
	if (!qname) {
		return ctx->state;
	}

	knot_db_val_t data = { pkt->wire, pkt->size };
	struct kr_cache_entry header = {
		.timestamp = qry->timestamp.tv_sec,
		.ttl = ttl,
		.rank = KR_RANK_AUTH,
		.flags = KR_CACHE_FLAG_NONE,
		.count = data.len
	};

	/* If cd bit is set or we got answer via non-validated forwarding,
	 * make the rank bad; otherwise it depends on flags. */
	if (knot_wire_get_cd(req->answer->wire) || qry->flags.STUB) {
		kr_rank_set(&header.rank, KR_RANK_OMIT);
	} else {
		if (qry->flags.DNSSEC_BOGUS) {
			kr_rank_set(&header.rank, KR_RANK_BOGUS);
		} else if (qry->flags.DNSSEC_INSECURE) {
			kr_rank_set(&header.rank, KR_RANK_INSECURE);
		} else if (qry->flags.DNSSEC_WANT) {
			kr_rank_set(&header.rank, KR_RANK_SECURE);
		}
	}
	VERBOSE_MSG(qry, "=> candidate rank: 0%0.2o\n", header.rank);

	/* Set cache flags */
	if (qry->flags.DNSSEC_WEXPAND) {
		header.flags |= KR_CACHE_FLAG_WCARD_PROOF;
	}
	if (qry->flags.DNSSEC_OPTOUT) {
		header.flags |= KR_CACHE_FLAG_OPTOUT;
	}

	/* Check if we can replace (allow current or better rank, SECURE is always accepted). */
	struct kr_cache *cache = &ctx->req->ctx->cache;
	if (header.rank < KR_RANK_SECURE) {
		int cached_rank = kr_cache_peek_rank
			(cache, KR_CACHE_PKT, qname, qtype, header.timestamp);
		if (cached_rank >= 0) {
			VERBOSE_MSG(qry, "=> cached rank:    0%0.2o\n", cached_rank);
			if (cached_rank > header.rank) {
				return ctx->state;
			}
		}
	}

	/* Stash answer in the cache */
	int ret1 = kr_cache_insert(cache, KR_CACHE_PKT, qname, qtype, &header, data);
	int ret2 = kr_cache_sync(cache);
	if (!ret1 && !ret2) {
		VERBOSE_MSG(qry, "=> answer cached for TTL=%u\n", ttl);
	} else {
		VERBOSE_MSG(qry, "=> stashing failed; codes: %d and %d\n", ret1, ret2);
	}
	return ctx->state;
}

/** Module implementation. */
const kr_layer_api_t *pktcache_layer(struct kr_module *module)
{
	static const kr_layer_api_t _layer = {
		.produce = &pktcache_peek,
		.consume = &pktcache_stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(pktcache)

#undef VERBOSE_MSG
