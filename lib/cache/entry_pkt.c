/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/** @file
 * Implementation of packet-caching.  Prototypes in ./impl.h
 *
 * The packet is stashed in entry_h::data as uint16_t length + full packet wire format.
 */

#include "lib/utils.h"
#include "lib/layer/iterate.h" /* kr_response_classify */
#include "lib/cache/impl.h"


/** Compute TTL for a packet.  Generally it's minimum TTL, with extra conditions. */
static uint32_t packet_ttl(const knot_pkt_t *pkt, bool is_negative)
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
					return MIN(knot_rrset_ttl(rr),
						   knot_soa_minimum(&rr->rrs));
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
				has_ttl = true;
				ttl = MIN(ttl, knot_rdata_ttl(rd));
				rd = kr_rdataset_next(rd);
			}
		}
	}
	/* If no valid TTL present, go with zero (will get clamped to minimum). */
	return has_ttl ? ttl : 0;
}



void stash_pkt(const knot_pkt_t *pkt, const struct kr_query *qry,
		const struct kr_request *req)
{
	/* In some cases, stash also the packet. */
	const bool is_negative = kr_response_classify(pkt)
				& (PKT_NODATA|PKT_NXDOMAIN);
	const bool want_pkt = qry->flags.DNSSEC_BOGUS
		|| (is_negative && (qry->flags.DNSSEC_INSECURE || !qry->flags.DNSSEC_WANT));

	/* Also stash packets that contain an NSEC3.
	 * LATER(NSEC3): remove when aggressive NSEC3 works. */
	bool with_nsec3 = false;
	if (!want_pkt && qry->flags.DNSSEC_WANT && !qry->flags.DNSSEC_BOGUS
	    && !qry->flags.DNSSEC_INSECURE) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (unsigned k = 0; k < sec->count; ++k) {
			if (knot_pkt_rr(sec, k)->type == KNOT_RRTYPE_NSEC3) {
				with_nsec3 = true;
				VERBOSE_MSG(qry, "NSEC3 found\n");
				break;
			}
		}
	}

	if (!(want_pkt || with_nsec3) || !knot_wire_get_aa(pkt->wire)
	    || pkt->parsed != pkt->size /* malformed packet; still can't detect KNOT_EFEWDATA */
	   ) {
		return;
	}

	/* Compute rank.  If cd bit is set or we got answer via non-validated
	 * forwarding, make the rank bad; otherwise it depends on flags.
	 * TODO: probably make validator attempt validation even with +cd. */
	uint8_t rank = KR_RANK_AUTH;
	const bool risky_vldr = is_negative && qry->flags.FORWARD && qry->flags.CNAME;
		/* ^^ CNAME'ed NXDOMAIN answer in forwarding mode can contain
		 * unvalidated records; original commit: d6e22f476. */
	if (knot_wire_get_cd(req->answer->wire) || qry->flags.STUB || risky_vldr) {
		kr_rank_set(&rank, KR_RANK_OMIT);
	} else {
		if (qry->flags.DNSSEC_BOGUS) {
			kr_rank_set(&rank, KR_RANK_BOGUS);
		} else if (qry->flags.DNSSEC_INSECURE) {
			kr_rank_set(&rank, KR_RANK_INSECURE);
		} else if (!qry->flags.DNSSEC_WANT) {
			/* no TAs at all, leave _RANK_AUTH */
		} else if (with_nsec3) {
			/* All bad cases should be filtered above,
			 * at least the same way as pktcache in kresd 1.5.x. */
			kr_rank_set(&rank, KR_RANK_SECURE);
		} else assert(false);
	}

	const uint16_t pkt_type = knot_pkt_qtype(pkt);
	const knot_dname_t *owner = knot_pkt_qname(pkt); /* qname can't be compressed */

	// LATER: nothing exists under NXDOMAIN.  Implement that (optionally)?
#if 0
	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN
	 /* && !qry->flags.DNSSEC_INSECURE */ ) {
		pkt_type = KNOT_RRTYPE_NS;
	}
#endif

	/* Construct the key under which the pkt will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	int ret = kr_dname_lf(k->buf, owner, false);
	if (ret) {
		/* A server might (incorrectly) reply with QDCOUNT=0. */
		assert(owner == NULL);
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
				owner, qry, cache);
	if (ret) return; /* some aren't really errors */
	assert(val_new_entry.data);
	struct entry_h *eh = val_new_entry.data;
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = MAX(MIN(packet_ttl(pkt, is_negative), cache->ttl_max), cache->ttl_min);
	eh->rank = rank;
	eh->is_packet = true;
	eh->has_optout = qry->flags.DNSSEC_OPTOUT;
	memcpy(eh->data, &pkt_size, sizeof(pkt_size));
	memcpy(eh->data + sizeof(pkt_size), pkt->wire, pkt_size);

	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> stashed packet: rank 0%0.2o, TTL %d, ",
				eh->rank, eh->ttl);
		kr_rrtype_print(pkt_type, "", " ");
		kr_dname_print(owner, "", " ");
		kr_log_verbose("(%d B)\n", (int)val_new_entry.len);
	}
}


int answer_from_pkt(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	uint16_t pkt_len;
	memcpy(&pkt_len, eh->data, sizeof(pkt_len));
	if (pkt_len > pkt->max_size) {
		return kr_error(ENOENT);
	}

	/* Copy answer and reparse it, but keep the original message id. */
	uint16_t msgid = knot_wire_get_id(pkt->wire);
	knot_pkt_clear(pkt);
	memcpy(pkt->wire, eh->data + 2, pkt_len);
	pkt->size = pkt_len;
	int ret = knot_pkt_parse(pkt, 0);
	if (ret == KNOT_EFEWDATA) {
		return kr_error(ENOENT); /* LATER(opt): avoid stashing such packets */
	}
	if (ret != KNOT_EOK) {
		assert(!ret);
		return kr_error(ret);
	}
	knot_wire_set_id(pkt->wire, msgid);

	/* Add rank into the additional field. */
	for (size_t i = 0; i < pkt->rrset_count; ++i) {
		assert(!pkt->rr[i].additional);
		uint8_t *rr_rank = mm_alloc(&pkt->mm, sizeof(*rr_rank));
		if (!rr_rank) {
			return kr_error(ENOMEM);
		}
		*rr_rank = eh->rank;
		pkt->rr[i].additional = rr_rank;
	}

	/* Adjust TTL in records.  We know that no RR has expired yet. */
	const uint32_t drift = eh->ttl - new_ttl;
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			knot_rdata_t *rd = rr->rrs.data;
			for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
				knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
				rd = kr_rdataset_next(rd);
			}
		}
	}

	/* Finishing touches. TODO: perhaps factor out */
	qry->flags.EXPIRING = is_expiring(eh->ttl, new_ttl);
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry->flags.DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	qry->flags.DNSSEC_BOGUS = kr_rank_test(eh->rank, KR_RANK_BOGUS);
	if (qry->flags.DNSSEC_INSECURE || qry->flags.DNSSEC_BOGUS) {
		qry->flags.DNSSEC_WANT = false;
	}
	qry->flags.DNSSEC_OPTOUT = eh->has_optout;
	VERBOSE_MSG(qry, "=> satisfied by exact packet: rank 0%0.2o, new TTL %d\n",
			eh->rank, new_ttl);
	return kr_ok();
}

