/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file iterate.c
 *
 * This builtin module is mainly active in the consume phase.
 * Primary responsibilities:
 *  - Classify the packet as auth/nonauth and change its AA flag accordingly.
 *  - Pick interesting RRs to kr_request::answ_selected and ::auth_selected,
 *    NEW: and classify their rank, except for validation status.
 *  - Update kr_query::zone_cut (in case of referral).
 *  - Interpret CNAMEs.
 *  - Prepare the followup query - either inline or as another kr_query
 *    (CNAME jumps create a new "sibling" query).
 */

#include <sys/time.h>
#include <assert.h>
#include <arpa/inet.h>

#include <contrib/cleanup.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "kresconfig.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/selection.h"
#include "lib/module.h"
#include "lib/dnssec/ta.h"

#define VERBOSE_MSG(...) QRVERBOSE(req->current_query, "iter", __VA_ARGS__)
#define QVERBOSE_MSG(qry, ...) QRVERBOSE(qry, "iter", __VA_ARGS__)

/* Iterator often walks through packet section, this is an abstraction. */
typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_request *);

/** Return minimized QNAME/QTYPE for current zone cut. */
static const knot_dname_t *minimized_qname(struct kr_query *query, uint16_t *qtype)
{
	/* Minimization disabled. */
	const knot_dname_t *qname = query->sname;
	if (qname[0] == '\0' || query->flags.NO_MINIMIZE || query->flags.STUB) {
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

	/* ID should already match, thanks to session_tasklist_del_msgid()
	 * in worker_submit(), but it won't hurt to check again. */
	return query->id      == knot_wire_get_id(answer->wire) &&
	       knot_wire_get_qdcount(answer->wire) == 1 &&
	       query->sclass  == knot_pkt_qclass(answer) &&
	       qtype          == knot_pkt_qtype(answer) &&
	       /* qry->secret had been xor-applied to answer already,
		* so this also checks for correctness of case randomization */
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
		if (rr->type == KNOT_RRTYPE_SOA
		    && knot_dname_in_bailiwick(rr->owner, query->zone_cut.name) >= 0) {
			return true;
		}
	}

	/* Some authoritative servers are hopelessly broken, allow lame answers in permissive mode. */
	if (query->flags.PERMISSIVE) {
		return true;
	}

	return false;
}

int kr_response_classify(const knot_pkt_t *pkt)
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
static int update_nsaddr(const knot_rrset_t *rr, struct kr_query *query, int *glue_cnt)
{
	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		const knot_rdata_t *rdata = rr->rrs.rdata;
		const int a_len = rr->type == KNOT_RRTYPE_A
			? sizeof(struct in_addr) : sizeof(struct in6_addr);
		if (a_len != rdata->len) {
			QVERBOSE_MSG(query, "<= ignoring invalid glue, length %d != %d\n",
					(int)rdata->len, a_len);
			return KR_STATE_FAIL;
		}
		char name_str[KR_DNAME_STR_MAXLEN];
		char addr_str[INET6_ADDRSTRLEN];
		WITH_VERBOSE(query) {
			const int af = (rr->type == KNOT_RRTYPE_A) ? AF_INET : AF_INET6;
			knot_dname_to_str(name_str, rr->owner, sizeof(name_str));
			name_str[sizeof(name_str) - 1] = 0;
			inet_ntop(af, rdata->data, addr_str, sizeof(addr_str));
		}
		if (!(query->flags.ALLOW_LOCAL) &&
			!is_valid_addr(rdata->data, rdata->len)) {
			QVERBOSE_MSG(query, "<= ignoring invalid glue for "
				     "'%s': '%s'\n", name_str, addr_str);
			return KR_STATE_CONSUME; /* Ignore invalid addresses */
		}
		int ret = kr_zonecut_add(&query->zone_cut, rr->owner, rdata->data, rdata->len);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}

		++*glue_cnt; /* reduced verbosity */
		/* QVERBOSE_MSG(query, "<= using glue for "
			     "'%s': '%s'\n", name_str, addr_str);
		*/
	}
	return KR_STATE_CONSUME;
}

/** @internal From \a pkt, fetch glue records for name \a ns, and update the cut etc.
 *
 * \param glue_cnt the number of accepted addresses (to be incremented)
 */
static void fetch_glue(knot_pkt_t *pkt, const knot_dname_t *ns, bool in_bailiwick,
			struct kr_request *req, const struct kr_query *qry, int *glue_cnt)
{
	ranked_rr_array_t *selected[] = kr_request_selected(req);
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

			uint8_t rank = (in_bailiwick && i == KNOT_ANSWER)
				? (KR_RANK_INITIAL | KR_RANK_AUTH) : KR_RANK_OMIT;
			(void) kr_ranked_rrarray_add(selected[i], rr, rank,
							false, qry->uid, &req->pool);

			if ((rr->type == KNOT_RRTYPE_A) &&
			    (req->ctx->options.NO_IPV4)) {
				QVERBOSE_MSG(qry, "<= skipping IPv4 glue due to network settings\n");
				continue;
			}
			if ((rr->type == KNOT_RRTYPE_AAAA) &&
			    (req->ctx->options.NO_IPV6)) {
				QVERBOSE_MSG(qry, "<= skipping IPv6 glue due to network settings\n");
				continue;
			}
			(void) update_nsaddr(rr, req->current_query, glue_cnt);
		}
	}
}

/** Attempt to find glue for given nameserver name (best effort). */
static bool has_glue(knot_pkt_t *pkt, const knot_dname_t *ns)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (knot_dname_is_equal(ns, rr->owner) &&
			    (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)) {
				return true;
			}
		}
	}
	return false;
}

/** @internal Update the cut with another NS(+glue) record.
 * @param current_cut is cut name before this packet.
 * @return _DONE if cut->name changes, _FAIL on error, and _CONSUME otherwise. */
static int update_cut(knot_pkt_t *pkt, const knot_rrset_t *rr,
		      struct kr_request *req, const knot_dname_t *current_cut,
		      int *glue_cnt)
{
	struct kr_query *qry = req->current_query;
	struct kr_zonecut *cut = &qry->zone_cut;
	int state = KR_STATE_CONSUME;

	/* New authority MUST be at/below the authority of the current cut;
	 * also qname must be below new authority;
	 * otherwise it's a possible cache injection attempt. */
	const bool ok = knot_dname_in_bailiwick(rr->owner, current_cut) >= 0
		     && knot_dname_in_bailiwick(qry->sname, rr->owner)  >= 0;
	if (!ok) {
		VERBOSE_MSG("<= authority: ns outside bailiwick\n");
		qry->server_selection.error(qry, req->upstream.transport, KR_SELECTION_LAME_DELEGATION);
		/* Workaround: ignore out-of-bailiwick NSs for authoritative answers,
		 * but fail for referrals. This is important to detect lame answers. */
		if (knot_pkt_section(pkt, KNOT_ANSWER)->count == 0) {
			state = KR_STATE_FAIL;
		}
		return state;
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
	knot_rdata_t *rdata_i = rr->rrs.rdata;
	for (unsigned i = 0; i < rr->rrs.count;
			++i, rdata_i = knot_rdataset_next(rdata_i)) {
		const knot_dname_t *ns_name = knot_ns_name(rdata_i);
		/* Glue is mandatory for NS below zone */
		if (knot_dname_in_bailiwick(ns_name, rr->owner) >= 0
		    && !has_glue(pkt, ns_name)) {
			const char *msg =
				"<= authority: missing mandatory glue, skipping NS";
			WITH_VERBOSE(qry) {
				auto_free char *ns_str = kr_dname_text(ns_name);
				VERBOSE_MSG("%s %s\n", msg, ns_str);
			}
			continue;
		}
		int ret = kr_zonecut_add(cut, ns_name, NULL, 0);
		assert(!ret); (void)ret;

		/* Choose when to use glue records. */
		const bool in_bailiwick =
			knot_dname_in_bailiwick(ns_name, current_cut) >= 0;
		bool do_fetch;
		if (qry->flags.PERMISSIVE) {
			do_fetch = true;
		} else if (qry->flags.STRICT) {
			/* Strict mode uses only mandatory glue. */
			do_fetch = knot_dname_in_bailiwick(ns_name, cut->name) >= 0;
		} else {
			/* Normal mode uses in-bailiwick glue. */
			do_fetch = in_bailiwick;
		}
		if (do_fetch) {
			fetch_glue(pkt, ns_name, in_bailiwick, req, qry, glue_cnt);
		}
	}

	return state;
}

/** Compute rank appropriate for RRs present in the packet.
 * @param answer whether the RR is from answer or authority section
 * @param is_nonauth: from referral or forwarding (etc.) */
static uint8_t get_initial_rank(const knot_rrset_t *rr, const struct kr_query *qry,
				const bool answer, const bool is_nonauth)
{
	/* For RRSIGs, ensure the KR_RANK_AUTH flag corresponds to the signed RR. */
	uint16_t type = kr_rrset_type_maysig(rr);

	if (qry->flags.CACHED) {
		return rr->additional ? *(uint8_t *)rr->additional : KR_RANK_OMIT;
		/* ^^ Current use case for "cached" RRs without rank: hints module. */
	}
	if (answer || type == KNOT_RRTYPE_DS
	    || type == KNOT_RRTYPE_SOA /* needed for aggressive negative caching */
	    || type == KNOT_RRTYPE_NSEC || type == KNOT_RRTYPE_NSEC3) {
		/* We almost always want these validated, and it should be possible. */
		return KR_RANK_INITIAL | KR_RANK_AUTH;
	}
	/* Be aggressive: try to validate anything else (almost never extra latency). */
	return KR_RANK_TRY;
	/* TODO: this classifier of authoritativity may not be perfect yet. */
}

static int pick_authority(knot_pkt_t *pkt, struct kr_request *req, bool to_wire)
{
	struct kr_query *qry = req->current_query;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);

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
		if (rr->rclass != KNOT_CLASS_IN
		    || knot_dname_in_bailiwick(rr->owner, zonecut_name) < 0) {
			continue;
		}
		uint8_t rank = get_initial_rank(rr, qry, false,
						qry->flags.FORWARD || referral);
		int ret = kr_ranked_rrarray_add(&req->auth_selected, rr,
						rank, to_wire, qry->uid, &req->pool);
		if (ret < 0) {
			return ret;
		}
	}

	return kr_ok();
}

static int process_authority(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *qry = req->current_query;
	assert(!(qry->flags.STUB));

	int result = KR_STATE_CONSUME;
	if (qry->flags.FORWARD) {
		return result;
	}

	/* One could _CONSUME if pkt has AA flag set here, but many authoritative
	 * servers are broken, so we employ several workarounds. */

	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);

	/* Work around servers sending back CNAME with different delegation and no AA. */
	if (an->count > 0 && ns->count > 0) {
		const knot_rrset_t *rr = knot_pkt_rr(an, 0);
		if (rr->type == KNOT_RRTYPE_CNAME) {
			return KR_STATE_CONSUME;
		}
		/* Work around for these NSs which are authoritative both for
		 * parent and child and mixes data from both zones in single answer */
		if (knot_wire_get_aa(pkt->wire) &&
		    (rr->type == qry->stype) &&
		    (knot_dname_is_equal(rr->owner, qry->sname))) {
			return KR_STATE_CONSUME;
		}
	}

	/* Remember current bailiwick for NS processing. */
	const knot_dname_t *current_zone_cut = qry->zone_cut.name;
	bool ns_record_exists = false;
	int glue_cnt = 0;
	/* Update zone cut information. */
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			ns_record_exists = true;
			int state = update_cut(pkt, rr, req, current_zone_cut, &glue_cnt);
			switch(state) {
			case KR_STATE_DONE: result = state; break;
			case KR_STATE_FAIL: return state; break;
			default:              /* continue */ break;
			}
		} else if (rr->type == KNOT_RRTYPE_SOA
			   && knot_dname_in_bailiwick(rr->owner, qry->zone_cut.name) > 0) {
			/* SOA below cut in authority indicates different authority,
			 * but same NS set. */
			qry->zone_cut.name = knot_dname_copy(rr->owner, &req->pool);
		}
	}

	/* Nameserver is authoritative for both parent side and the child side of the
	 * delegation may respond with an NS record in the answer section, and still update
	 * the zone cut (e.g. what a.gtld-servers.net would respond for `com NS`) */
	if (!ns_record_exists && knot_wire_get_aa(pkt->wire)) {
		for (unsigned i = 0; i < an->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(an, i);
			if (rr->type == KNOT_RRTYPE_NS
			    && knot_dname_in_bailiwick(rr->owner, qry->zone_cut.name) > 0) {
				/* NS below cut in authority indicates different authority,
				 * but same NS set. */
				qry->zone_cut.name = knot_dname_copy(rr->owner, &req->pool);
			}
		}
	}

	if (glue_cnt) {
		VERBOSE_MSG("<= loaded %d glue addresses\n", glue_cnt);
	}


	if ((qry->flags.DNSSEC_WANT) && (result == KR_STATE_CONSUME)) {
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

static int finalize_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	/* Finalize header */
	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (answer) {
		knot_wire_set_rcode(answer->wire, knot_wire_get_rcode(pkt->wire));
		req->state = KR_STATE_DONE;
	}
	return req->state;
}

static int unroll_cname(knot_pkt_t *pkt, struct kr_request *req, bool referral, const knot_dname_t **cname_ret)
{
	struct kr_query *query = req->current_query;
	assert(!(query->flags.STUB));
	/* Process answer type */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_dname_t *cname = NULL;
	const knot_dname_t *pending_cname = query->sname;
	bool is_final = (query->parent == NULL);
	bool strict_mode = (query->flags.STRICT);

	query->cname_depth = query->cname_parent ? query->cname_parent->cname_depth : 1;

	do {
		/* CNAME was found at previous iteration, but records may not follow the correct order.
		 * Try to find records for pending_cname owner from section start. */
		cname = pending_cname;
		size_t cname_answ_selected_i = -1;
		bool cname_is_occluded = false; /* whether `cname` is in a DNAME's bailiwick */
		pending_cname = NULL;
		const int cname_labels = knot_dname_labels(cname, NULL);
		for (unsigned i = 0; i < an->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(an, i);

			/* Skip the RR if its owner+type doesn't interest us. */
			const uint16_t type = kr_rrset_type_maysig(rr);
			const bool type_OK = rr->type == query->stype || type == query->stype
						|| type == KNOT_RRTYPE_CNAME;
			if (rr->rclass != KNOT_CLASS_IN
			    || knot_dname_in_bailiwick(rr->owner, query->zone_cut.name) < 0) {
				continue;
			}
			const bool all_OK = type_OK && knot_dname_is_equal(rr->owner, cname);

			const bool to_wire = is_final && !referral;

			if (!all_OK && type == KNOT_RRTYPE_DNAME
					&& knot_dname_in_bailiwick(cname, rr->owner) >= 1) {
				/* This DNAME (or RRSIGs) cover the current target (`cname`),
				 * so it is interesting and will occlude its CNAME.
				 * We rely on CNAME being sent along with DNAME
				 * (mandatory unless YXDOMAIN). */
				cname_is_occluded = true;
				uint8_t rank = get_initial_rank(rr, query, true,
						query->flags.FORWARD || referral);
				int ret = kr_ranked_rrarray_add(&req->answ_selected, rr,
						rank, to_wire, query->uid, &req->pool);
				if (ret < 0) {
					return KR_STATE_FAIL;
				}
			}
			if (!all_OK) {
				continue;
			}

			if (rr->type == KNOT_RRTYPE_RRSIG) {
				int rrsig_labels = knot_rrsig_labels(rr->rrs.rdata);
				if (rrsig_labels > cname_labels) {
					/* clearly wrong RRSIG, don't pick it.
					 * don't fail immediately,
					 * let validator work. */
					continue;
				}
				if (rrsig_labels < cname_labels) {
					query->flags.DNSSEC_WEXPAND = true;
				}
			}

			/* Process records matching current SNAME */
			if (!is_final) {
				int cnt_ = 0;
				int state = update_nsaddr(rr, query->parent, &cnt_);
				if (state & KR_STATE_FAIL) {
					return state;
				}
			}
			uint8_t rank = get_initial_rank(rr, query, true,
					query->flags.FORWARD || referral);
			int ret = kr_ranked_rrarray_add(&req->answ_selected, rr,
						rank, to_wire, query->uid, &req->pool);
			if (ret < 0) {
				return KR_STATE_FAIL;
			}
			cname_answ_selected_i = ret;

			/* Select the next CNAME target, but don't jump immediately.
			 * There can be records for "old" cname (RRSIGs are interesting);
			 * more importantly there might be a DNAME for `cname_is_occluded`. */
			if (query->stype != KNOT_RRTYPE_CNAME && rr->type == KNOT_RRTYPE_CNAME) {
				pending_cname = knot_cname_name(rr->rrs.rdata);
				if (!pending_cname) {
					break;
				}
			}
		}
		if (!pending_cname) {
			break;
		}
		if (cname_is_occluded) {
			req->answ_selected.at[cname_answ_selected_i]->dont_cache = true;
		}
		if (++(query->cname_depth) > KR_CNAME_CHAIN_LIMIT) {
			VERBOSE_MSG("<= error: CNAME chain exceeded max length %d\n",
					/* people count objects from 0, no CNAME = 0 */
					(int)KR_CNAME_CHAIN_LIMIT - 1);
			return KR_STATE_FAIL;
		}

		if (knot_dname_is_equal(cname, pending_cname)) {
			VERBOSE_MSG("<= error: CNAME chain loop detected\n");
			return KR_STATE_FAIL;
		}
		/* In strict mode, explicitly fetch each CNAME target. */
		if (strict_mode) {
			cname = pending_cname;
			break;
		}
		/* Information outside bailiwick is not trusted. */
		if (knot_dname_in_bailiwick(pending_cname, query->zone_cut.name) < 0) {
			cname = pending_cname;
			break;
		}
		/* The validator still can't handle multiple zones in one answer,
		 * so we only follow if a single label is replaced.
		 * Forwarding appears to be even more sensitive to this.
		 * TODO: iteration can probably handle the remaining cases,
		 * but overall it would be better to have a smarter validator
		 * (and thus save roundtrips).*/
		const int pending_labels = knot_dname_labels(pending_cname, NULL);
		if (pending_labels != cname_labels) {
			cname = pending_cname;
			break;
		}
		if (knot_dname_matched_labels(pending_cname, cname) != cname_labels - 1
		    || query->flags.FORWARD) {
			cname = pending_cname;
			break;
		}
	} while (true);
	*cname_ret = cname;
	return kr_ok();
}

static int process_referral_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	const knot_dname_t *cname = NULL;
	int state = unroll_cname(pkt, req, true, &cname);
	struct kr_query *query = req->current_query;
	if (state != kr_ok()) {
		query->server_selection.error(query, req->upstream.transport, KR_SELECTION_BAD_CNAME);
		return KR_STATE_FAIL;
	}
	if (!(query->flags.CACHED)) {
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
		return finalize_answer(pkt, req);
	}
	return kr_ok();
}

static int process_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = req->current_query;

	/* Response for minimized QNAME.  Note that current iterator's minimization
	 * is only able ask one label below a zone cut.
	 * NODATA   => may be empty non-terminal, retry (found zone cut)
	 * NOERROR  => found zone cut, retry, except the case described below
	 * NXDOMAIN => parent is zone cut, retry as a workaround for bad authoritatives
	 */
	const bool is_final = (query->parent == NULL);
	const int pkt_class = kr_response_classify(pkt);
	const knot_dname_t * pkt_qname = knot_pkt_qname(pkt);
	if (!knot_dname_is_equal(pkt_qname, query->sname) &&
	    (pkt_class & (PKT_NOERROR|PKT_NXDOMAIN|PKT_REFUSED|PKT_NODATA))) {
		/* Check for parent server that is authoritative for child zone,
		 * several CCTLDs where the SLD and TLD have the same name servers */
		const knot_pktsection_t *ans = knot_pkt_section(pkt, KNOT_ANSWER);
		if ((pkt_class & (PKT_NOERROR)) && ans->count > 0 &&
		     knot_dname_is_equal(pkt_qname, query->zone_cut.name)) {
			VERBOSE_MSG("<= continuing with qname minimization\n");
		} else {
			/* fall back to disabling minimization */
			VERBOSE_MSG("<= retrying with non-minimized name\n");
			query->flags.NO_MINIMIZE = true;
		}
		return KR_STATE_CONSUME;
	}

	/* This answer didn't improve resolution chain, therefore must be authoritative (relaxed to negative). */
	if (!is_authoritative(pkt, query)) {
		if (!(query->flags.FORWARD) &&
		    pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) {
			query->server_selection.error(query, req->upstream.transport, KR_SELECTION_LAME_DELEGATION);
			VERBOSE_MSG("<= lame response: non-auth sent negative response\n");
			return KR_STATE_FAIL;
		}
	}

	const knot_dname_t *cname = NULL;
	/* Process answer type */
	int state = unroll_cname(pkt, req, false, &cname);
	if (state != kr_ok()) {
		query->server_selection.error(query, req->upstream.transport, KR_SELECTION_BAD_CNAME);
		return state;
	}
	/* Make sure that this is an authoritative answer (even with AA=0) for other layers */
	knot_wire_set_aa(pkt->wire);
	/* Either way it resolves current query. */
	query->flags.RESOLVED = true;
	/* Follow canonical name as next SNAME. */
	if (!knot_dname_is_equal(cname, query->sname)) {
		/* Check if target record has been already copied */
		query->flags.CNAME = true;
		if (is_final) {
			state = process_final(pkt, req, cname);
			if (state != kr_ok()) {
				return state;
			}
		} else if ((query->flags.FORWARD) &&
			   ((query->stype == KNOT_RRTYPE_DS) ||
			    (query->stype == KNOT_RRTYPE_NS))) {
			/* CNAME'ed answer for DS or NS subquery.
			 * Treat it as proof of zonecut nonexistance. */
			return KR_STATE_DONE;
		}
		VERBOSE_MSG("<= cname chain, following\n");
		/* Check if the same query was followed in the same CNAME chain. */
		for (const struct kr_query *q = query->cname_parent; q != NULL;
				q = q->cname_parent) {
			if (q->sclass == query->sclass &&
			    q->stype == query->stype   &&
			    knot_dname_is_equal(q->sname, cname)) {
				VERBOSE_MSG("<= cname chain loop\n");
				query->server_selection.error(query, req->upstream.transport, KR_SELECTION_BAD_CNAME);
				return KR_STATE_FAIL;
			}
		}
		struct kr_query *next = kr_rplan_push(&req->rplan, query->parent, cname, query->sclass, query->stype);
		if (!next) {
			return KR_STATE_FAIL;
		}
		next->flags.AWAIT_CUT = true;

		/* Copy transitive flags from original query to CNAME followup. */
		next->flags.TRACE = query->flags.TRACE;
		next->flags.ALWAYS_CUT = query->flags.ALWAYS_CUT;

		/* Original query might have turned minimization off, revert. */
		next->flags.NO_MINIMIZE = req->options.NO_MINIMIZE;

		if (query->flags.FORWARD) {
			next->forward_flags.CNAME = true;
		}
		next->cname_parent = query;
		/* Want DNSSEC if and only if it's posible to secure
		 * this name (i.e. iff it is covered by a TA) */
		if (kr_ta_covers_qry(req->ctx, cname, query->stype)) {
			next->flags.DNSSEC_WANT = true;
		} else {
			next->flags.DNSSEC_WANT = false;
		}
		if (!(query->flags.FORWARD) ||
		    (query->flags.DNSSEC_WEXPAND)) {
			state = pick_authority(pkt, req, false);
			if (state != kr_ok()) {
				return KR_STATE_FAIL;
			}
		}
	} else if (!query->parent) {
		/* Answer for initial query */
		const bool to_wire = ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) != 0);
		state = pick_authority(pkt, req, to_wire);
		if (state != kr_ok()) {
			return KR_STATE_FAIL;
		}
		return finalize_answer(pkt, req);
	} else {
		/* Answer for sub-query; DS, IP for NS etc.
		 * It may contains NSEC \ NSEC3 records for
		 * data non-existence or wc expansion proving.
		 * If yes, they must be validated by validator.
		 * If no, authority section is unuseful.
		 * dnssec\nsec.c & dnssec\nsec3.c use
		 * rrsets from incoming packet.
		 * validator uses answer_selected & auth_selected.
		 * So, if nsec\nsec3 records are present in authority,
		 * pick_authority() must be called.
		 * TODO refactor nsec\nsec3 modules to work with
		 * answer_selected & auth_selected instead of incoming pkt. */
		bool auth_is_unuseful = true;
		const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (unsigned i = 0; i < ns->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);
			if (rr->type == KNOT_RRTYPE_NSEC ||
			    rr->type == KNOT_RRTYPE_NSEC3) {
				auth_is_unuseful = false;
				break;
			}
		}
		if (!auth_is_unuseful) {
			state = pick_authority(pkt, req, false);
			if (state != kr_ok()) {
				return KR_STATE_FAIL;
			}
		}
	}
	return KR_STATE_DONE;
}

/** @internal like process_answer() but for the STUB mode. */
static int process_stub(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = req->current_query;
	assert(query->flags.STUB);
	/* Pick all answer RRs. */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		int err = kr_ranked_rrarray_add(&req->answ_selected, rr,
			      KR_RANK_OMIT | KR_RANK_AUTH, true, query->uid, &req->pool);
		/* KR_RANK_AUTH: we don't have the records directly from
		 * an authoritative source, but we do trust the server and it's
		 * supposed to only send us authoritative records. */
		if (err < 0) {
			return KR_STATE_FAIL;
		}
	}

	knot_wire_set_aa(pkt->wire);
	query->flags.RESOLVED = true;
	/* Pick authority RRs. */
	int pkt_class = kr_response_classify(pkt);
	const bool to_wire = ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) != 0);
	int err = pick_authority(pkt, req, to_wire);
	if (err != kr_ok()) {
		return KR_STATE_FAIL;
	}

	return finalize_answer(pkt, req);
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
		knot_pkt_t *ans = kr_request_ensure_answer(ctx->req);
		if (!ans) return ctx->req->state;
		knot_wire_set_rcode(ans->wire, KNOT_RCODE_NOTIMPL);
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
	query->id = kr_rand_bytes(2);
	/* We must respect https://tools.ietf.org/html/rfc7766#section-6.2.1
	 * -  When sending multiple queries over a TCP connection, clients MUST NOT
	 *    reuse the DNS Message ID of an in-flight query on that connection.
	 *
	 * So, if query is going to be sent over TCP connection
	 * this id can be changed to avoid duplication with query that already was sent
	 * but didn't receive answer yet.
	 */
	knot_wire_set_id(pkt->wire, query->id);
	pkt->parsed = pkt->size;

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

	WITH_VERBOSE(query) {
		KR_DNAME_GET_STR(name_str, query->sname);
		KR_RRTYPE_GET_STR(type_str, query->stype);
		QVERBOSE_MSG(query, "'%s' type '%s' new uid was assigned .%02u, parent uid .%02u\n",
			    name_str, type_str, req->rplan.next_uid,
			    query->parent ? query->parent->uid : 0);
	}

	query->uid = req->rplan.next_uid;
	req->rplan.next_uid += 1;
	query->flags.CACHED = false; // in case it got left from earlier (unknown edge case)

	return KR_STATE_CONSUME;
}

static bool satisfied_by_additional(const struct kr_query *qry)
{
	const bool prereq = !qry->flags.STUB && !qry->flags.FORWARD && qry->flags.NONAUTH;
	if (!prereq)
		return false;
	const struct kr_request *req = qry->request;
	for (ssize_t i = req->add_selected.len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *entry = req->add_selected.at[i];
		if (entry->qry_uid != qry->uid)
			break;
		if (entry->rr->type == qry->stype
		    && knot_dname_is_equal(entry->rr->owner, qry->sname)) {
			return true;
		}
	}
	return false;
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
	query->flags.PKT_IS_SANE = false;

	WITH_VERBOSE(query) {
		if (query->flags.TRACE) {
			auto_free char *pkt_text = kr_pkt_text(pkt);
			VERBOSE_MSG("<= answer received: \n%s\n", pkt_text);
		}
	}

	if (query->flags.RESOLVED || query->flags.BADCOOKIE_AGAIN) {
		return ctx->state;
	}

	/* Check for packet processing errors first.
	 * Note - we *MUST* check if it has at least a QUESTION,
	 * otherwise it would crash on accessing QNAME. */
	if (pkt->parsed <= KNOT_WIRE_HEADER_SIZE) {
		if (pkt->parsed == KNOT_WIRE_HEADER_SIZE && knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_FORMERR) {
			/* This is a special case where we get valid header with FORMERR and nothing else.
			 * This happens on some authoritatives which don't support EDNS and don't
			 * bother copying the SECTION QUESTION. */
			query->server_selection.error(query, req->upstream.transport, KR_SELECTION_FORMERR);
			return KR_STATE_FAIL;
		}
		VERBOSE_MSG("<= malformed response (parsed %d)\n", (int)pkt->parsed);
		query->server_selection.error(query, req->upstream.transport, KR_SELECTION_MALFORMED);
		return KR_STATE_FAIL;
	} else if (!is_paired_to_query(pkt, query)) {
		WITH_VERBOSE(query) {
			const char *ns_str =
				req->upstream.transport ? kr_straddr(&req->upstream.transport->address.ip) : "(internal)";
			VERBOSE_MSG("<= ignoring mismatching response from %s\n",
					ns_str ? ns_str : "(kr_straddr failed)");
		}
		query->server_selection.error(query, req->upstream.transport, KR_SELECTION_MISMATCHED);
		return KR_STATE_FAIL;
	} else if (knot_wire_get_tc(pkt->wire)) {
		VERBOSE_MSG("<= truncated response, failover to TCP\n");
		if (query) {
			/* Fail if already on TCP. */
			if (req->upstream.transport->protocol != KR_TRANSPORT_UDP) {
				VERBOSE_MSG("<= TC=1 with TCP, bailing out\n");
				query->server_selection.error(query, req->upstream.transport, KR_SELECTION_TRUNCATED);
				return KR_STATE_FAIL;
			}
			query->server_selection.error(query, req->upstream.transport, KR_SELECTION_TRUNCATED);
		}
		return KR_STATE_CONSUME;
	}

	/* If exiting above here, there's no sense to put it into packet cache.
	 * The most important part is to check for spoofing: is_paired_to_query() */
	query->flags.PKT_IS_SANE = true;

#ifndef NOVERBOSELOG
	const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, knot_wire_get_rcode(pkt->wire));
#endif

	// We can't return directly from the switch because we have to give feedback to server selection first
	int ret = 0;
	int selection_error = KR_SELECTION_OK;

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	case KNOT_RCODE_YXDOMAIN: /* Basically a successful answer; name just doesn't fit. */
		if (!kr_request_ensure_answer(req)) {
			ret = req->state;
		}
		knot_wire_set_rcode(req->answer->wire, KNOT_RCODE_YXDOMAIN);
		break;
	case KNOT_RCODE_REFUSED:
		if (query->flags.STUB) {
			 /* just pass answer through if in stub mode */
			break;
		}
		ret = KR_STATE_FAIL;
		selection_error = KR_SELECTION_REFUSED;
		break;
	case KNOT_RCODE_SERVFAIL:
		if (query->flags.STUB) {
			 /* just pass answer through if in stub mode */
			break;
		}
		ret = KR_STATE_FAIL;
		selection_error = KR_SELECTION_SERVFAIL;
		break;
	case KNOT_RCODE_FORMERR:
		ret = KR_STATE_FAIL;
		if (knot_pkt_has_edns(pkt)) {
			selection_error = KR_SELECTION_FORMERR_EDNS;
		} else {
			selection_error = KR_SELECTION_FORMERR;
		}
		break;
	case KNOT_RCODE_NOTIMPL:
		ret = KR_STATE_FAIL;
		selection_error = KR_SELECTION_NOTIMPL;
		break;
	default:
		ret = KR_STATE_FAIL;
		selection_error = KR_SELECTION_OTHER_RCODE;
		break;
	}

	if (query->server_selection.initialized) {
		query->server_selection.error(query, req->upstream.transport, selection_error);
	}

	if (ret) {
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return ret;
	}

	if (pkt->parsed < pkt->size) {
		VERBOSE_MSG("<= ignoring packet due to containing excessive data (%zu bytes)\n",
				pkt->size - pkt->parsed);
		return KR_STATE_FAIL;
	}

	int state;
	/* Forwarding/stub mode is special. */
	if (query->flags.STUB) {
		state = process_stub(pkt, req);
		goto rrarray_finalize;
	}

	/* Resolve authority to see if it's referral or authoritative. */
	state = process_authority(pkt, req);
	switch(state) {
	case KR_STATE_CONSUME: /* Not referral, process answer. */
		VERBOSE_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		state = process_answer(pkt, req);
		break;
	case KR_STATE_DONE: /* Referral */
		state = process_referral_answer(pkt,req);
		if (satisfied_by_additional(query)) { /* This is a little hacky.
			 * We found sufficient information in ADDITIONAL section
			 * and it was selected for caching in this CONSUME round.
			 * To make iterator accept the record in a simple way,
			 * we trigger another cache *reading* attempt
			 * for the subsequent PRODUCE round.
			 */
			assert(query->flags.NONAUTH);
			query->flags.CACHE_TRIED = false;
			VERBOSE_MSG("<= referral response, but cache should stop us short now\n");
		} else {
			VERBOSE_MSG("<= referral response, follow\n");
		}
		break;
	default:
		break;
	}

rrarray_finalize:
	/* Finish construction of libknot-format RRsets.
	 * We do this even if dropping the answer, though it's probably useless. */
	(void)0;
	ranked_rr_array_t *selected[] = kr_request_selected(req);
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		ret = kr_ranked_rrarray_finalize(selected[i], query->uid, &req->pool);
		if (unlikely(ret)) {
			return KR_STATE_FAIL;
		}
	}

	return state;
}

/** Module implementation. */
int iterate_init(struct kr_module *self)
{
	static const kr_layer_api_t layer = {
		.begin = &begin,
		.reset = &reset,
		.consume = &resolve,
		.produce = &prepare_query
	};
	self->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(iterate) /* useless for builtin module, but let's be consistent */

#undef VERBOSE_MSG
