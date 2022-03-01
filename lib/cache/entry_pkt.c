/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Implementation of packet-caching.  Prototypes in ./impl.h
 *
 * The packet is stashed in entry_h::data as uint16_t length + full packet wire format.
 */

#include "lib/utils.h"
#include "lib/layer/iterate.h" /* kr_response_classify */
#include "lib/cache/impl.h"


/** Compute TTL for a packet.  Generally it's minimum TTL, with extra conditions. */
KR_EXPORT
uint32_t packet_ttl(const knot_pkt_t *pkt, bool is_negative)
{
	bool has_ttl = false;
	uint32_t ttl = TTL_MAX_MAX;
	/* Find minimum entry TTL in the packet or SOA minimum TTL. */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (is_negative) {
				/* Use SOA minimum TTL for negative answers. */
				if (rr->type == KNOT_RRTYPE_SOA) {
					return MIN(rr->ttl, knot_soa_minimum(rr->rrs.rdata));
				} else {
					continue; /* Use SOA only for negative answers. */
				}
			}
			if (knot_rrtype_is_metatype(rr->type)) {
				continue; /* Skip metatypes. */
			}
			ttl = MIN(ttl, rr->ttl);
			has_ttl = true;
		}
	}
	/* If no valid TTL present, go with zero (will get clamped to minimum). */
	return has_ttl ? ttl : 0;
}


void stash_pkt(const knot_pkt_t *pkt, const struct kr_query *qry,
		const struct kr_request *req, const bool needs_pkt)
{
	/* In some cases, stash also the packet. */
	const bool is_negative = kr_response_classify(pkt)
				& (PKT_NODATA|PKT_NXDOMAIN);
	const struct kr_qflags * const qf = &qry->flags;
	const bool want_negative = qf->DNSSEC_INSECURE || !qf->DNSSEC_WANT;
	const bool want_pkt = qf->DNSSEC_BOGUS /*< useful for +cd answers */
				|| (is_negative && want_negative) || needs_pkt;

	if (!want_pkt || !knot_wire_get_aa(pkt->wire)
	    || pkt->parsed != pkt->size /*< malformed packet; still can't detect KNOT_EFEWDATA */
	   ) {
		return;
	}

	/* Compute rank.  If cd bit is set or we got answer via non-validated
	 * forwarding, make the rank bad; otherwise it depends on flags.
	 * TODO: probably make validator attempt validation even with +cd. */
	uint8_t rank = KR_RANK_AUTH;
	const bool risky_vldr = is_negative && qf->FORWARD && qf->CNAME;
		/* ^^ CNAME'ed NXDOMAIN answer in forwarding mode can contain
		 * unvalidated records; original commit: d6e22f476. */
	if (knot_wire_get_cd(req->qsource.packet->wire) || qf->STUB || risky_vldr) {
		kr_rank_set(&rank, KR_RANK_OMIT);
	} else {
		if (qf->DNSSEC_BOGUS) {
			kr_rank_set(&rank, KR_RANK_BOGUS);
		} else if (qf->DNSSEC_INSECURE) {
			kr_rank_set(&rank, KR_RANK_INSECURE);
		} else if (!qf->DNSSEC_WANT) {
			/* no TAs at all, leave _RANK_AUTH */
		} else if (needs_pkt) {
			/* All bad cases should be filtered above,
			 * at least the same way as pktcache in kresd 1.5.x. */
			kr_rank_set(&rank, KR_RANK_SECURE);
		} else kr_assert(false);
	}

	const uint16_t pkt_type = knot_pkt_qtype(pkt);
	const knot_dname_t *owner = knot_pkt_qname(pkt); /* qname can't be compressed */

	// LATER: nothing exists under NXDOMAIN.  Implement that (optionally)?
#if 0
	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN
	 /* && !qf->DNSSEC_INSECURE */ ) {
		pkt_type = KNOT_RRTYPE_NS;
	}
#endif

	/* Construct the key under which the pkt will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	int ret = kr_dname_lf(k->buf, owner, false);
	if (ret) {
		/* A server might (incorrectly) reply with QDCOUNT=0. */
		kr_assert(owner == NULL);
		return;
	}
	key = key_exact_type_maypkt(k, pkt_type);

	/* For now we stash the full packet byte-exactly as it came from upstream. */
	const uint16_t pkt_size = pkt->size;
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + sizeof(pkt_size) + pkt->size,
	};
	/* Prepare raw memory for the new entry and fill it. */
	struct kr_cache *cache = &req->ctx->cache;
	ret = entry_h_splice(&val_new_entry, rank, key, k->type, pkt_type,
				owner, qry, cache, qry->timestamp.tv_sec);
	if (ret || kr_fails_assert(val_new_entry.data)) return; /* some aren't really errors */
	struct entry_h *eh = val_new_entry.data;
	memset(eh, 0, offsetof(struct entry_h, data));
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = MAX(MIN(packet_ttl(pkt, is_negative), cache->ttl_max), cache->ttl_min);
	eh->rank = rank;
	eh->is_packet = true;
	eh->has_optout = qf->DNSSEC_OPTOUT;
	memcpy(eh->data, &pkt_size, sizeof(pkt_size));
	memcpy(eh->data + sizeof(pkt_size), pkt->wire, pkt_size);

	WITH_VERBOSE(qry) {
		auto_free char *type_str = kr_rrtype_text(pkt_type),
			*owner_str = kr_dname_text(owner);
		VERBOSE_MSG(qry, "=> stashed packet: rank 0%.2o, TTL %d, "
				"%s %s (%d B)\n",
				eh->rank, eh->ttl,
				type_str, owner_str, (int)val_new_entry.len);
	}
}


int answer_from_pkt(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	const uint16_t msgid = knot_wire_get_id(pkt->wire);

	/* Ensure the wire buffer is large enough.  Strategy: fit and at least double. */
	uint16_t pkt_len;
	memcpy(&pkt_len, eh->data, sizeof(pkt_len));
	if (pkt_len > pkt->max_size) {
		pkt->max_size = MIN(KNOT_WIRE_MAX_PKTSIZE,
				    MAX(pkt->max_size * 2, pkt_len));
		mm_free(&ctx->req->pool, pkt->wire); /* no-op, but... */
		pkt->wire = mm_alloc(&ctx->req->pool, pkt->max_size);
		pkt->compr.wire = pkt->wire;
		/* TODO: ^^ nicer way how to replace knot_pkt_t::wire ? */
	}
	kr_require(pkt->max_size >= pkt_len);

	/* Copy answer and reparse it, but keep the original message id. */
	knot_pkt_clear(pkt);
	memcpy(pkt->wire, eh->data + 2, pkt_len);
	pkt->size = pkt_len;
	int ret = knot_pkt_parse(pkt, 0);
	if (ret == KNOT_EFEWDATA || ret == KNOT_EMALF) {
		return kr_error(ENOENT);
		/* LATER(opt): try harder to avoid stashing such packets */
	}
	if (kr_fails_assert(ret == KNOT_EOK))
		return kr_error(ret);
	knot_wire_set_id(pkt->wire, msgid);

	/* Add rank into the additional field. */
	for (size_t i = 0; i < pkt->rrset_count; ++i) {
		kr_assert(!pkt->rr[i].additional);
		uint8_t *rr_rank = mm_alloc(&pkt->mm, sizeof(*rr_rank));
		if (!rr_rank) {
			return kr_error(ENOMEM);
		}
		*rr_rank = eh->rank;
		pkt->rr[i].additional = rr_rank;
	}

	/* Adjust TTL in each record. */
	const uint32_t drift = eh->ttl - new_ttl;
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			knot_rrset_t *rrs = // vv FIXME??
				/*const-cast*/(knot_rrset_t *)knot_pkt_rr(sec, k);
			/* We need to be careful: due to enforcing minimum TTL
			 * on packet, some records may be below that value.
			 * We keep those records at TTL 0. */
			if (rrs->ttl >= drift) {
				rrs->ttl -= drift;
			} else {
				rrs->ttl = 0;
			}
		}
	}

	/* Finishing touches. TODO: perhaps factor out */
	struct kr_qflags * const qf = &qry->flags;
	qf->EXPIRING = is_expiring(eh->ttl, new_ttl);
	qf->CACHED = true;
	qf->NO_MINIMIZE = true;
	qf->DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	qf->DNSSEC_BOGUS = kr_rank_test(eh->rank, KR_RANK_BOGUS);
	if (qf->DNSSEC_INSECURE || qf->DNSSEC_BOGUS) {
		qf->DNSSEC_WANT = false;
	}
	qf->DNSSEC_OPTOUT = eh->has_optout;
	VERBOSE_MSG(qry, "=> satisfied by exact packet: rank 0%.2o, new TTL %d\n",
			eh->rank, new_ttl);
	return kr_ok();
}

