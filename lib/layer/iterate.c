/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/time.h>
#include <assert.h>
#include <arpa/inet.h>

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"
#include "lib/dnssec/ta.h"

#define VERBOSE_MSG(fmt...) QRVERBOSE(req->current_query, "iter", fmt)
#define QVERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "iter", fmt)

/* Iterator often walks through packet section, this is an abstraction. */
typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_request *);

/** Return minimized QNAME/QTYPE for current zone cut. */
static const knot_dname_t *minimized_qname(struct kr_query *query, uint16_t *qtype)
{
	/* Minimization disabled. */
	const knot_dname_t *qname = query->sname;
	if (qname[0] == '\0' || query->flags & (QUERY_NO_MINIMIZE|QUERY_STUB)) {
		return qname;
	}

	/* Minimize name to contain current zone cut + 1 label. */
	int cut_labels = knot_dname_labels(query->zone_cut.name, NULL);
	int qname_labels = knot_dname_labels(qname, NULL);
	while(qname[0] && qname_labels > cut_labels + 1) {
		qname = knot_wire_next_label(qname, NULL);
		qname_labels -= 1;
	}

	/* Hide QTYPE if minimized. */
	if (qname != query->sname) {
		*qtype = KNOT_RRTYPE_NS;
	}

	return qname;
}

/** Answer is paired to query. */
static bool is_paired_to_query(const knot_pkt_t *answer, struct kr_query *query)
{
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	return query->id      == knot_wire_get_id(answer->wire) &&
	       knot_wire_get_qdcount(answer->wire) > 0 &&
	       query->sclass  == knot_pkt_qclass(answer) &&
	       qtype          == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(qname, knot_pkt_qname(answer));
}

/** Relaxed rule for AA, either AA=1 or SOA matching zone cut is required. */
static bool is_authoritative(const knot_pkt_t *answer, struct kr_query *query)
{
	if (knot_wire_get_aa(answer->wire)) {
		return true;
	}

	const knot_pktsection_t *ns = knot_pkt_section(answer, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_SOA && knot_dname_in(query->zone_cut.name, rr->owner)) {
			return true;
		}
	}

#ifndef STRICT_MODE
	/* Last resort to work around broken auths, if the zone cut is at/parent of the QNAME. */
	if (knot_dname_is_equal(query->zone_cut.name, knot_pkt_qname(answer))) {
		return true;
	}
#endif
	return false;
}

int kr_response_classify(knot_pkt_t *pkt)
{
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	switch (knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
		return (an->count == 0) ? PKT_NODATA : PKT_NOERROR;
	case KNOT_RCODE_NXDOMAIN:
		return PKT_NXDOMAIN;
	case KNOT_RCODE_REFUSED:
		return PKT_REFUSED;
	default:
		return PKT_ERROR;
	}
}

/** @internal Filter ANY or loopback addresses. */
static bool is_valid_addr(const uint8_t *addr, size_t len)
{
	if (len == sizeof(struct in_addr)) {
		/* Filter ANY and 127.0.0.0/8 */
		uint32_t ip_host = ntohl(*(const uint32_t *)(addr));
		if (ip_host == 0 || (ip_host & 0xff000000) == 0x7f000000) {
			return false;
		}
	} else if (len == sizeof(struct in6_addr)) {
		struct in6_addr ip6_mask;
		memset(&ip6_mask, 0, sizeof(ip6_mask));
		/* All except last byte are zeroed, last byte defines ANY/::1 */
		if (memcmp(addr, ip6_mask.s6_addr, sizeof(ip6_mask.s6_addr) - 1) == 0) {
			return (addr[len - 1] > 1);
		}
	}
	return true;
}

/** @internal Update NS address from record \a rr.  Return _FAIL on error. */
static int update_nsaddr(const knot_rrset_t *rr, struct kr_query *query)
{
	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		const knot_rdata_t *rdata = rr->rrs.data;
		const void *addr = knot_rdata_data(rdata);
		const int addr_len = knot_rdata_rdlen(rdata);
		char name_str[KNOT_DNAME_MAXLEN];
		char addr_str[INET6_ADDRSTRLEN];
		WITH_VERBOSE {
			const int af = (addr_len == sizeof(struct in_addr)) ?
				       AF_INET : AF_INET6;
			knot_dname_to_str(name_str, rr->owner, sizeof(name_str));
			inet_ntop(af, addr, addr_str, sizeof(addr_str));
		}
		if (!(query->flags & QUERY_ALLOW_LOCAL) &&
			!is_valid_addr(addr, addr_len)) {
			QVERBOSE_MSG(query, "<= ignoring invalid glue for "
				     "'%s': '%s'\n", name_str, addr_str);
			return KR_STATE_CONSUME; /* Ignore invalid addresses */
		}
		int ret = kr_zonecut_add(&query->zone_cut, rr->owner, rdata);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}
		QVERBOSE_MSG(query, "<= using glue for "
			     "'%s': '%s'\n", name_str, addr_str);
	}
	return KR_STATE_CONSUME;
}

/** @internal From \a pkt, fetch glue records for name \a ns, and update the cut etc. */
static void fetch_glue(knot_pkt_t *pkt, const knot_dname_t *ns, struct kr_request *req)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (!knot_dname_is_equal(ns, rr->owner)) {
				continue;
			}
			if ((rr->type != KNOT_RRTYPE_A) &&
			    (rr->type != KNOT_RRTYPE_AAAA)) {
				continue;
			}
			if ((rr->type == KNOT_RRTYPE_A) &&
			    (req->ctx->options & QUERY_NO_IPV4)) {
				continue;
			}
			if ((rr->type == KNOT_RRTYPE_AAAA) &&
			    (req->ctx->options & QUERY_NO_IPV6)) {
				continue;
			}
			(void) update_nsaddr(rr, req->current_query);
		}
	}
}

/** Attempt to find glue for given nameserver name (best effort). */
static int has_glue(knot_pkt_t *pkt, const knot_dname_t *ns)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (knot_dname_is_equal(ns, rr->owner) &&
			    (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)) {
				return 1;
			}
		}
	}
	return 0;
}

/** @internal Update the cut with another NS(+glue) record.
 * @param current_cut is cut name before this packet.
 * @return _DONE if cut->name changes, _FAIL on error, and _CONSUME otherwise. */
static int update_cut(knot_pkt_t *pkt, const knot_rrset_t *rr,
		      struct kr_request *req, const knot_dname_t *current_cut)
{
	struct kr_query *qry = req->current_query;
	struct kr_zonecut *cut = &qry->zone_cut;
	int state = KR_STATE_CONSUME;

	/* New authority MUST be at/below the authority of the current cut;
	 * also qname must be below new authority;
	 * otherwise it's a possible cache injection attempt. */
	if (!knot_dname_in(current_cut, rr->owner) ||
	    !knot_dname_in(rr->owner, qry->sname)) {
		VERBOSE_MSG("<= authority: ns outside bailiwick\n");
#ifdef STRICT_MODE
		return KR_STATE_FAIL;
#else
		/* Workaround: ignore out-of-bailiwick NSs for authoritative answers,
		 * but fail for referrals. This is important to detect lame answers. */
		if (knot_pkt_section(pkt, KNOT_ANSWER)->count == 0) {
			state = KR_STATE_FAIL;
		}
		return state;
#endif
	}

	/* Update zone cut name */
	if (!knot_dname_is_equal(rr->owner, cut->name)) {
		/* Remember parent cut and descend to new (keep keys and TA). */
		struct kr_zonecut *parent = mm_alloc(&req->pool, sizeof(*parent));
		if (parent) {
			memcpy(parent, cut, sizeof(*parent));
			kr_zonecut_init(cut, rr->owner, &req->pool);
			cut->key = parent->key;
			cut->trust_anchor = parent->trust_anchor;
			cut->parent = parent;
		} else {
			kr_zonecut_set(cut, rr->owner);
		}
		state = KR_STATE_DONE;
	}

	/* Fetch glue for each NS */
	for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, i);
		int glue_records = has_glue(pkt, ns_name);
		/* Glue is mandatory for NS below zone */
		if (!glue_records && knot_dname_in(rr->owner, ns_name)) {
			VERBOSE_MSG("<= authority: missing mandatory glue, rejecting\n");
			continue;
		}
		kr_zonecut_add(cut, ns_name, NULL);
		/* Choose when to use glue records. */
		if (qry->flags & QUERY_PERMISSIVE) {
			fetch_glue(pkt, ns_name, req);
		} else if (qry->flags & QUERY_STRICT) {
			/* Strict mode uses only mandatory glue. */
			if (knot_dname_in(cut->name, ns_name))
				fetch_glue(pkt, ns_name, req);
		} else {
			/* Normal mode uses in-bailiwick glue. */
			if (knot_dname_in(current_cut, ns_name))
				fetch_glue(pkt, ns_name, req);
		}
	}

	return state;
}

static int pick_authority(knot_pkt_t *pkt, struct kr_request *req, bool to_wire)
{
	struct kr_query *qry = req->current_query;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	uint8_t rank = !(qry->flags & QUERY_DNSSEC_WANT) || (qry->flags & QUERY_CACHED) ?
			KR_VLDRANK_SECURE : KR_VLDRANK_INITIAL;
	const knot_dname_t *zonecut_name = qry->zone_cut.name;
	bool referral = !knot_wire_get_aa(pkt->wire);
	if (referral) {
		/* zone cut already updated by process_authority()
		 * use parent zonecut name */
		zonecut_name = qry->zone_cut.parent ? qry->zone_cut.parent->name : qry->zone_cut.name;
		to_wire = false;
	}

	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (!knot_dname_in(zonecut_name, rr->owner)) {
			continue;
		}
		int ret = kr_ranked_rrarray_add(&req->auth_selected, rr,
						rank, to_wire, qry->uid, &req->pool);
		if (ret != kr_ok()) {
			return ret;
		}
	}

	return kr_ok();
}

static int process_authority(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *qry = req->current_query;
	assert(!(qry->flags & QUERY_STUB));

	int result = KR_STATE_CONSUME;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);

#ifdef STRICT_MODE
	/* AA, terminate resolution chain. */
	if (knot_wire_get_aa(pkt->wire)) {
		return KR_STATE_CONSUME;
	}
#else

	/* Work around servers sending back CNAME with different delegation and no AA. */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	if (an->count > 0 && ns->count > 0) {
		const knot_rrset_t *rr = knot_pkt_rr(an, 0);
		if (rr->type == KNOT_RRTYPE_CNAME) {
			return KR_STATE_CONSUME;
		}
	}
#endif
	/* Remember current bailiwick for NS processing. */
	const knot_dname_t *current_zone_cut = qry->zone_cut.name;
	bool ns_record_exists = false;
	/* Update zone cut information. */
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			ns_record_exists = true;
			int state = update_cut(pkt, rr, req, current_zone_cut);
			switch(state) {
			case KR_STATE_DONE: result = state; break;
			case KR_STATE_FAIL: return state; break;
			default:              /* continue */ break;
			}
		} else if (rr->type == KNOT_RRTYPE_SOA && knot_dname_is_sub(rr->owner, qry->zone_cut.name)) {
			/* SOA below cut in authority indicates different authority, but same NS set. */
			qry->zone_cut.name = knot_dname_copy(rr->owner, &req->pool);
		}
	}


	if ((qry->flags & QUERY_DNSSEC_WANT) && (result == KR_STATE_CONSUME)) {
		if (knot_wire_get_aa(pkt->wire) == 0 &&
		    knot_wire_get_ancount(pkt->wire) == 0 &&
		    ns_record_exists) {
			/* Unhelpful referral
			   Prevent from validating as an authoritative answer */
			result = KR_STATE_DONE;
		}
	}

	/* CONSUME => Unhelpful referral.
	 * DONE    => Zone cut updated.  */
	return result;
}

static void finalize_answer(knot_pkt_t *pkt, struct kr_query *qry, struct kr_request *req)
{
	/* Finalize header */
	knot_pkt_t *answer = req->answer;
	knot_wire_set_rcode(answer->wire, knot_wire_get_rcode(pkt->wire));
}

static int unroll_cname(knot_pkt_t *pkt, struct kr_request *req, bool referral, const knot_dname_t **cname_ret)
{
	struct kr_query *query = req->current_query;
	assert(!(query->flags & QUERY_STUB));
	/* Process answer type */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_dname_t *cname = NULL;
	const knot_dname_t *pending_cname = query->sname;
	unsigned cname_chain_len = 0;
	uint8_t rank = !(query->flags & QUERY_DNSSEC_WANT) || (query->flags & QUERY_CACHED) ?
			KR_VLDRANK_SECURE : KR_VLDRANK_INITIAL;
	bool is_final = (query->parent == NULL);
	uint32_t iter_count = 0;
	bool strict_mode = (query->flags & QUERY_STRICT);
	do {
		/* CNAME was found at previous iteration, but records may not follow the correct order.
		 * Try to find records for pending_cname owner from section start. */
		cname = pending_cname;
		pending_cname = NULL;
		for (unsigned i = 0; i < an->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(an, i);

			/* Skip the RR if its owner+type doesn't interest us. */
			const uint16_t type = kr_rrset_type_maysig(rr);
			const bool type_OK = rr->type == query->stype || type == query->stype
				|| type == KNOT_RRTYPE_CNAME || type == KNOT_RRTYPE_DNAME;
				/* TODO: actually handle DNAMEs */
			if (!type_OK || !knot_dname_is_equal(rr->owner, cname)) {
				continue;
			}

			/* Process records matching current SNAME */
			int state = KR_STATE_FAIL;
			bool to_wire = false;
			if (is_final) {
				/* if not referral, mark record to be written to final answer */
				to_wire = !referral;
			} else {
				state = update_nsaddr(rr, query->parent);
				if (state == KR_STATE_FAIL) {
					return state;
				}
			}
			state = kr_ranked_rrarray_add(&req->answ_selected, rr,
						      rank, to_wire, query->uid, &req->pool);
			if (state != kr_ok()) {
				return KR_STATE_FAIL;
			}
			/* Jump to next CNAME target */
			if ((query->stype == KNOT_RRTYPE_CNAME) || (rr->type != KNOT_RRTYPE_CNAME)) {
				continue;
			}
			cname_chain_len += 1;
			pending_cname = knot_cname_name(&rr->rrs);
			if (!pending_cname) {
				break;
			}
			if (cname_chain_len > an->count || cname_chain_len > KR_CNAME_CHAIN_LIMIT) {
				VERBOSE_MSG("<= too long cname chain\n");
				return KR_STATE_FAIL;
			}
			/* Don't use pending_cname immediately.
			 * There are can be records for "old" cname. */
		}
		if (!pending_cname) {
			break;
		}
		if (knot_dname_is_equal(cname, pending_cname)) {
			VERBOSE_MSG("<= cname chain loop\n");
			return KR_STATE_FAIL;
		}
		/* In strict mode, explicitly fetch each CNAME target. */
		if (strict_mode) {
			cname = pending_cname;
			break;
		}
		/* try to unroll cname only within current zone */
		const int pending_labels = knot_dname_labels(pending_cname, NULL);
		const int cname_labels = knot_dname_labels(cname, NULL);
		if (pending_labels != cname_labels) {
			cname = pending_cname;
			break;
		}
		if (knot_dname_matched_labels(pending_cname, cname) !=
		    (cname_labels - 1)) {
			cname = pending_cname;
			break;
		}
	} while (++iter_count < KR_CNAME_CHAIN_LIMIT);
	if (iter_count >= KR_CNAME_CHAIN_LIMIT) {
		VERBOSE_MSG("<= too long cname chain\n");
		return KR_STATE_FAIL;
	}
	*cname_ret = cname;
	return kr_ok();
}

static int process_referral_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	const knot_dname_t *cname = NULL;
	int state = unroll_cname(pkt, req, true, &cname);
	if (state != kr_ok()) {
		return KR_STATE_FAIL;
	}
	struct kr_query *query = req->current_query;
	if (!(query->flags & QUERY_CACHED)) {
		/* If not cached (i.e. got from upstream)
		 * make sure that this is not an authoritative answer
		 * (even with AA=1) for other layers.
		 * There can be answers with AA=1,
		 * empty answer section and NS in authority.
		 * Clearing of AA prevents them from
		 * caching in the packet cache.
		 * If packet already cached, don't touch him. */
		knot_wire_clear_aa(pkt->wire);
	}
	state = pick_authority(pkt, req, false);
	return state == kr_ok() ? KR_STATE_DONE : KR_STATE_FAIL;
}

static int process_final(knot_pkt_t *pkt, struct kr_request *req,
			 const knot_dname_t *cname)
{
	const int pkt_class = kr_response_classify(pkt);
	struct kr_query *query = req->current_query;
	ranked_rr_array_t *array = &req->answ_selected;
	for (size_t i = 0; i < array->len; ++i) {
		const knot_rrset_t *rr = array->at[i]->rr;
		if (!knot_dname_is_equal(rr->owner, cname)) {
			continue;
		}
		if ((rr->rclass != query->sclass) ||
		    (rr->type != query->stype)) {
			continue;
		}
		const bool to_wire = ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) != 0);
		const int state = pick_authority(pkt, req, to_wire);
		if (state != kr_ok()) {
			return KR_STATE_FAIL;
		}
		if (!array->at[i]->to_wire) {
			const size_t last_idx = array->len - 1;
			size_t j = i;
			ranked_rr_array_entry_t *entry = array->at[i];
			/* Relocate record to the end, after current cname */
			while (j < last_idx) {
				array->at[j] = array->at[j + 1];
				++j;
			}
			array->at[last_idx] = entry;
			entry->to_wire = true;
		}
		finalize_answer(pkt, query, req);
		return KR_STATE_DONE;
	}
	return kr_ok();
}

static int process_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = req->current_query;

	/* Response for minimized QNAME.
	 * NODATA   => may be empty non-terminal, retry (found zone cut)
	 * NOERROR  => found zone cut, retry
	 * NXDOMAIN => parent is zone cut, retry as a workaround for bad authoritatives
	 */
	bool is_final = (query->parent == NULL);
	int pkt_class = kr_response_classify(pkt);
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), query->sname) &&
	    (pkt_class & (PKT_NOERROR|PKT_NXDOMAIN|PKT_REFUSED|PKT_NODATA))) {
		VERBOSE_MSG("<= found cut, retrying with non-minimized name\n");
		query->flags |= QUERY_NO_MINIMIZE;
		return KR_STATE_CONSUME;
	}

	/* This answer didn't improve resolution chain, therefore must be authoritative (relaxed to negative). */
	if (!is_authoritative(pkt, query)) {
		if (pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) {
			VERBOSE_MSG("<= lame response: non-auth sent negative response\n");
			return KR_STATE_FAIL;
		}
	}

	const knot_dname_t *cname = NULL;
	/* Process answer type */
	int state = unroll_cname(pkt, req, false, &cname);
	if (state != kr_ok()) {
		return state;
	}
	/* Make sure that this is an authoritative answer (even with AA=0) for other layers */
	knot_wire_set_aa(pkt->wire);
	/* Either way it resolves current query. */
	query->flags |= QUERY_RESOLVED;
	/* Follow canonical name as next SNAME. */
	if (!knot_dname_is_equal(cname, query->sname)) {
		/* Check if target record has been already copied */
		query->flags |= QUERY_CNAME;
		if (is_final) {
			state = process_final(pkt, req, cname);
			if (state != kr_ok()) {
				return state;
			}
		}
		VERBOSE_MSG("<= cname chain, following\n");
		/* Check if the same query was already resolved */
		for (int i = 0; i < req->rplan.resolved.len; ++i) {
			struct kr_query * q = req->rplan.resolved.at[i];
			if (q->parent == query->parent &&
			    q->sclass == query->sclass &&
			    q->stype == query->stype   &&
			    knot_dname_is_equal(q->sname, cname)) {
				VERBOSE_MSG("<= cname chain loop\n");
				return KR_STATE_FAIL;
			}
		}
		struct kr_query *next = kr_rplan_push(&req->rplan, query->parent, cname, query->sclass, query->stype);
		if (!next) {
			return KR_STATE_FAIL;
		}
		next->flags |= QUERY_AWAIT_CUT;
		if (query->flags & QUERY_DNSSEC_INSECURE) {
			next->flags &= ~QUERY_DNSSEC_WANT;
			next->flags |= QUERY_DNSSEC_INSECURE;
		} else if (kr_ta_covers(&req->ctx->trust_anchors, cname) &&
		    !kr_ta_covers(&req->ctx->negative_anchors, cname)) {
			/* Want DNSSEC if it's posible to secure
			 * this name (e.g. is covered by any TA) */
			next->flags |= QUERY_DNSSEC_WANT;
		}
		state = pick_authority(pkt, req, false);
		if (state != kr_ok()) {
			return KR_STATE_FAIL;
		}
	} else if (!query->parent) {
		const bool to_wire = ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) != 0);
		state = pick_authority(pkt, req, to_wire);
		if (state != kr_ok()) {
			return KR_STATE_FAIL;
		}
		finalize_answer(pkt, query, req);
	} else {
		state = pick_authority(pkt, req, false);
		if (state != kr_ok()) {
			return KR_STATE_FAIL;
		}
	}
	return KR_STATE_DONE;
}

/** @internal like process_answer() but for the forwarding mode. */
static int process_stub(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = req->current_query;
	assert(query->flags & QUERY_STUB);
	/* Pick all answer RRs. */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		int err = kr_ranked_rrarray_add(&req->answ_selected, rr,
			      KR_VLDRANK_INITIAL, true, query->uid, &req->pool);
		if (err != kr_ok()) {
			return KR_STATE_FAIL;
		}
	}

	knot_wire_set_aa(pkt->wire);
	query->flags |= QUERY_RESOLVED;
	/* Pick authority RRs. */
	int pkt_class = kr_response_classify(pkt);
	const bool to_wire = ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) != 0);
	int err = pick_authority(pkt, req, to_wire);
	if (err != kr_ok()) {
		return KR_STATE_FAIL;
	}

	finalize_answer(pkt, query, req);
	return KR_STATE_DONE;
}


/** Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_request *req)
{
	return KR_STATE_FAIL;
}

/* State-less single resolution iteration step, not needed. */
static int reset(kr_layer_t *ctx)  { return KR_STATE_PRODUCE; }

/* Set resolution context and parameters. */
static int begin(kr_layer_t *ctx)
{
	if (ctx->state & (KR_STATE_DONE|KR_STATE_FAIL)) {
		return ctx->state;
	}
	/*
	 * RFC7873 5.4 extends the QUERY operation code behaviour in order to
	 * be able to generate requests for server cookies. Such requests have
	 * QDCOUNT equal to zero and must contain a cookie option.
	 * Server cookie queries must be handled by the cookie module/layer
	 * before this layer.
	 */
	const knot_pkt_t *pkt = ctx->req->qsource.packet;
	if (!pkt || knot_wire_get_qdcount(pkt->wire) == 0) {
		return KR_STATE_FAIL;
	}

	struct kr_query *qry = ctx->req->current_query;
	/* Avoid any other classes, and avoid any meta-types ~~except for ANY~~. */
	if (qry->sclass != KNOT_CLASS_IN
	    || (knot_rrtype_is_metatype(qry->stype)
		    /* && qry->stype != KNOT_RRTYPE_ANY hmm ANY seems broken ATM */)) {
		knot_wire_set_rcode(ctx->req->answer->wire, KNOT_RCODE_NOTIMPL);
		return KR_STATE_FAIL;
	}

	return reset(ctx);
}

int kr_make_query(struct kr_query *query, knot_pkt_t *pkt)
{
	/* Minimize QNAME (if possible). */
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	/* Form a query for the authoritative. */
	knot_pkt_clear(pkt);
	int ret = knot_pkt_put_question(pkt, qname, query->sclass, qtype);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Query built, expect answer. */
	query->id = kr_rand_uint(UINT16_MAX);
	knot_wire_set_id(pkt->wire, query->id);
	pkt->parsed = pkt->size;
	WITH_VERBOSE {
		char name_str[KNOT_DNAME_MAXLEN], type_str[16];
		knot_dname_to_str(name_str, query->sname, sizeof(name_str));
		knot_rrtype_to_string(query->stype, type_str, sizeof(type_str));
		QVERBOSE_MSG(query, "'%s' type '%s' id was assigned, parent id %hu\n",
			    name_str, type_str, query->parent ? query->parent->id : 0);
	}
	return kr_ok();
}

static int prepare_query(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->req;
	struct kr_query *query = req->current_query;
	if (!query || ctx->state & (KR_STATE_DONE|KR_STATE_FAIL)) {
		return ctx->state;
	}

	/* Make query */
	int ret = kr_make_query(query, pkt);
	if (ret != 0) {
		return KR_STATE_FAIL;
	}

	query->uid = req->rplan.next_uid;
	req->rplan.next_uid += 1;

	return KR_STATE_CONSUME;
}

static int resolve_badmsg(knot_pkt_t *pkt, struct kr_request *req, struct kr_query *query)
{

#ifndef STRICT_MODE
	/* Work around broken auths/load balancers */
	if (query->flags & QUERY_SAFEMODE) {
		return resolve_error(pkt, req);
	} else if (query->flags & QUERY_NO_MINIMIZE) {
		query->flags |= QUERY_SAFEMODE;
		return KR_STATE_DONE;
	} else {
		query->flags |= QUERY_NO_MINIMIZE;
		return KR_STATE_DONE;
	}
#else
		return resolve_error(pkt, req);
#endif
}

/** Resolve input query or continue resolution with followups.
 *
 *  This roughly corresponds to RFC1034, 5.3.3 4a-d.
 */
static int resolve(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->req;
	struct kr_query *query = req->current_query;
	if (!query) {
		return ctx->state;
	}

	WITH_VERBOSE {
	if (query->flags & QUERY_TRACE) {
		VERBOSE_MSG("<= answer received:\n");
		kr_pkt_print(pkt);
	}
	}

	if (query->flags & (QUERY_RESOLVED|QUERY_BADCOOKIE_AGAIN)) {
		return ctx->state;
	}

	/* Check for packet processing errors first.
	 * Note - we *MUST* check if it has at least a QUESTION,
	 * otherwise it would crash on accessing QNAME. */
#ifdef STRICT_MODE
	if (pkt->parsed < pkt->size) {
		VERBOSE_MSG("<= pkt contains excessive data\n");
		return resolve_badmsg(pkt, req, query);
	} else
#endif
	if (pkt->parsed <= KNOT_WIRE_HEADER_SIZE) {
		VERBOSE_MSG("<= malformed response\n");
		return resolve_badmsg(pkt, req, query);
	} else if (!is_paired_to_query(pkt, query)) {
		VERBOSE_MSG("<= ignoring mismatching response\n");
		/* Force TCP, to work around authoritatives messing up question
		 * without yielding to spoofed responses. */
		query->flags |= QUERY_TCP;
		return resolve_badmsg(pkt, req, query);
	} else if (knot_wire_get_tc(pkt->wire)) {
		VERBOSE_MSG("<= truncated response, failover to TCP\n");
		if (query) {
			/* Fail if already on TCP. */
			if (query->flags & QUERY_TCP) {
				VERBOSE_MSG("<= TC=1 with TCP, bailing out\n");
				return resolve_error(pkt, req);
			}
			query->flags |= QUERY_TCP;
		}
		return KR_STATE_CONSUME;
	}

#ifndef NOVERBOSELOG
	const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, knot_wire_get_rcode(pkt->wire));
#endif

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	case KNOT_RCODE_REFUSED:
	case KNOT_RCODE_SERVFAIL: {
		if (query->flags & QUERY_STUB) { break; } /* Pass through in stub mode */
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		query->fails += 1;
		if (query->fails >= KR_QUERY_NSRETRY_LIMIT) {
			query->fails = 0; /* Reset per-query counter. */
			return resolve_error(pkt, req);
		} else {
			query->flags |= QUERY_NO_MINIMIZE; /* Drop minimisation as a safe-guard. */
			return KR_STATE_CONSUME;
		}
	}
	case KNOT_RCODE_FORMERR:
	case KNOT_RCODE_NOTIMPL:
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_badmsg(pkt, req, query);
	default:
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_error(pkt, req);
	}

	/* Forwarding/stub mode is special. */
	if (query->flags & QUERY_STUB) {
		return process_stub(pkt, req);
	}

	/* Resolve authority to see if it's referral or authoritative. */
	int state = process_authority(pkt, req);
	switch(state) {
	case KR_STATE_CONSUME: /* Not referral, process answer. */
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		state = process_answer(pkt, req);
		break;
	case KR_STATE_DONE: /* Referral */
		state = process_referral_answer(pkt,req);
		VERBOSE_MSG("<= referral response, follow\n");
		break;
	default:
		break;
	}

	return state;
}

/** Module implementation. */
const kr_layer_api_t *iterate_layer(struct kr_module *module)
{
	static const kr_layer_api_t _layer = {
		.begin = &begin,
		.reset = &reset,
		.consume = &resolve,
		.produce = &prepare_query
	};
	return &_layer;
}

KR_MODULE_EXPORT(iterate)

#undef VERBOSE_MSG
