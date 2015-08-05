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

#include <sys/time.h>

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>

#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(&req->rplan), "iter", fmt)

/* Iterator often walks through packet section, this is an abstraction. */
typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_request *);

/** Return minimized QNAME/QTYPE for current zone cut. */
static const knot_dname_t *minimized_qname(struct kr_query *query, uint16_t *qtype)
{
	/* Minimization disabled. */
	const knot_dname_t *qname = query->sname;
	if (qname[0] == '\0' || query->flags & QUERY_NO_MINIMIZE) {
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
	       (query->sclass == KNOT_CLASS_ANY || query->sclass  == knot_pkt_qclass(answer)) &&
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

static void follow_cname_chain(const knot_dname_t **cname, const knot_rrset_t *rr,
                               struct kr_query *cur)
{
	if (rr->type == KNOT_RRTYPE_CNAME) {
		*cname = knot_cname_name(&rr->rrs);
	} else {
		/* Terminate CNAME chain. */
		*cname = cur->sname;
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

static int update_nsaddr(const knot_rrset_t *rr, struct kr_query *query)
{
	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		const knot_rdata_t *rdata = rr->rrs.data;
		if (!(query->flags & QUERY_ALLOW_LOCAL) &&
			!is_valid_addr(knot_rdata_data(rdata), knot_rdata_rdlen(rdata))) {
			return KNOT_STATE_CONSUME; /* Ignore invalid addresses */
		}
		int ret = kr_zonecut_add(&query->zone_cut, rr->owner, rdata);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
	}

	return KNOT_STATE_CONSUME;
}

static int update_parent(const knot_rrset_t *rr, struct kr_request *req)
{
	struct kr_query *qry = kr_rplan_current(&req->rplan);
	return update_nsaddr(rr, qry->parent);
}

static int update_answer(const knot_rrset_t *rr, unsigned hint, struct kr_request *req)
{
	knot_pkt_t *answer = req->answer;
	int ret = knot_pkt_put(answer, hint, rr, 0);
	if (ret != KNOT_EOK) {
		knot_wire_set_tc(answer->wire);
		return KNOT_STATE_DONE;
	}

	return KNOT_STATE_DONE;
}

static void fetch_glue(knot_pkt_t *pkt, const knot_dname_t *ns, struct kr_query *qry)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (knot_dname_is_equal(ns, rr->owner)) {
				(void) update_nsaddr(rr, qry);
			}
		}
	}
}

/** Attempt to find glue for given nameserver name (best effort). */
static int has_glue(knot_pkt_t *pkt, const knot_dname_t *ns, struct kr_request *req)
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

static int update_cut(knot_pkt_t *pkt, const knot_rrset_t *rr, struct kr_request *req)
{
	struct kr_query *query = kr_rplan_current(&req->rplan);	
	struct kr_zonecut *cut = &query->zone_cut;
	int state = KNOT_STATE_CONSUME;

	/* Authority MUST be at/below the authority of the nameserver, otherwise
	 * possible cache injection attempt. */
	if (!knot_dname_in(cut->name, rr->owner)) {
		DEBUG_MSG("<= authority: ns outside bailiwick, ignoring\n");
		return state;
	}

	/* Update zone cut name */
	if (!knot_dname_is_equal(rr->owner, cut->name)) {
		kr_zonecut_set(cut, rr->owner);
		state = KNOT_STATE_DONE;
	}

	/* Fetch glue for each NS */
	for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, i);
		int glue_records = has_glue(pkt, ns_name, req);
		/* Glue is mandatory for NS below zone */
		if (!glue_records && knot_dname_in(rr->owner, ns_name)) {
			DEBUG_MSG("<= authority: missing mandatory glue, rejecting\n");
			continue;
		}
		kr_zonecut_add(cut, ns_name, NULL);
		fetch_glue(pkt, ns_name, query);
	}

	return state;
}

static int process_authority(knot_pkt_t *pkt, struct kr_request *req)
{
	int result = KNOT_STATE_CONSUME;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);

#ifdef STRICT_MODE
	/* AA, terminate resolution chain. */
	if (knot_wire_get_aa(pkt->wire)) {
		return KNOT_STATE_CONSUME;
	}
#else
	/* Work around servers sending back CNAME with different delegation and no AA. */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	if (an->count > 0 && ns->count > 0) {
		const knot_rrset_t *rr = knot_pkt_rr(an, 0);
		if (rr->type == KNOT_RRTYPE_CNAME) {
			return KNOT_STATE_CONSUME;
		}
	}
#endif

	/* Update zone cut information. */
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			int state = update_cut(pkt, rr, req);
			switch(state) {
			case KNOT_STATE_DONE: result = state; break;
			case KNOT_STATE_FAIL: return state; break;
			default:              /* continue */ break;
			}
		}
	}

	/* CONSUME => Unhelpful referral.
	 * DONE    => Zone cut updated. */
	return result;
}

static void finalize_answer(knot_pkt_t *pkt, struct kr_query *qry, struct kr_request *req)
{
	/* Finalize header */
	knot_pkt_t *answer = req->answer;
	knot_wire_set_rcode(answer->wire, knot_wire_get_rcode(pkt->wire));

	/* Fill in bailiwick records in authority */
	struct kr_zonecut *cut = &qry->zone_cut;
	knot_pkt_begin(answer, KNOT_AUTHORITY);
	int pkt_class = kr_response_classify(pkt);
	if (pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) {
		const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (unsigned i = 0; i < ns->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);
			if (knot_dname_in(cut->name, rr->owner)) {
				update_answer(rr, 0, req);
			}
		}
	}
}

static int process_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = kr_rplan_current(&req->rplan);

	/* Response for minimized QNAME.
	 * NODATA   => may be empty non-terminal, retry (found zone cut)
	 * NOERROR  => found zone cut, retry
	 * NXDOMAIN => parent is zone cut, retry as a workaround for bad authoritatives
	 */
	bool is_final = (query->parent == NULL);
	int pkt_class = kr_response_classify(pkt);
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), query->sname) &&
	    (pkt_class & (PKT_NOERROR|PKT_NXDOMAIN|PKT_REFUSED|PKT_NODATA))) {
		DEBUG_MSG("<= found cut, retrying with non-minimized name\n");
		query->flags |= QUERY_NO_MINIMIZE;
		return KNOT_STATE_DONE;
	}

	/* This answer didn't improve resolution chain, therefore must be authoritative (relaxed to negative). */
	if (!is_authoritative(pkt, query)) {
		if (pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) {
			DEBUG_MSG("<= lame response: non-auth sent negative response\n");
			return KNOT_STATE_FAIL;
		}
	}

	/* Process answer type */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_dname_t *cname = query->sname;
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		if (!knot_dname_is_equal(rr->owner, cname)) {
			continue;
		}
		unsigned hint = 0;
		if(knot_dname_is_equal(cname, knot_pkt_qname(req->answer))) {
			hint = KNOT_COMPR_HINT_QNAME;
		}
		int state = is_final ? update_answer(rr, hint, req) : update_parent(rr, req);
		if (state == KNOT_STATE_FAIL) {
			return state;
		}
		follow_cname_chain(&cname, rr, query);
	}

	/* Make sure that this is an authoritative naswer (even with AA=0) for other layers */
	knot_wire_set_aa(pkt->wire);
	/* Either way it resolves current query. */
	query->flags |= QUERY_RESOLVED;
	/* Follow canonical name as next SNAME. */
	if (!knot_dname_is_equal(cname, query->sname)) {
		DEBUG_MSG("<= cname chain, following\n");
		struct kr_query *next = kr_rplan_push(&req->rplan, query->parent, cname, query->sclass, query->stype);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		rem_node(&query->node); /* *MUST* keep current query at tail */
		insert_node(&query->node, &next->node);
		next->flags |= QUERY_AWAIT_CUT;
	} else if (!query->parent) {
		finalize_answer(pkt, query, req);
	}
	return KNOT_STATE_DONE;
}

/** Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_request *req)
{
	return KNOT_STATE_FAIL;
}

/* State-less single resolution iteration step, not needed. */
static int reset(knot_layer_t *ctx)  { return KNOT_STATE_PRODUCE; }
static int finish(knot_layer_t *ctx) { return KNOT_STATE_NOOP; }

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
	if (ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
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
	return kr_ok();
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = kr_rplan_current(&req->rplan);
	if (!query || ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}

	/* Make query */
	int ret = kr_make_query(query, pkt);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_CONSUME;
}

static int resolve_badmsg(knot_pkt_t *pkt, struct kr_request *req, struct kr_query *query)
{
#ifndef STRICT_MODE
	/* Work around broken auths/load balancers */
	if (query->flags & QUERY_SAFEMODE) {
		return resolve_error(pkt, req);
	} else {
		query->flags |= QUERY_SAFEMODE;
		return KNOT_STATE_DONE;
	}
#else
		return resolve_error(pkt, req);
#endif
}

/** Resolve input query or continue resolution with followups.
 *
 *  This roughly corresponds to RFC1034, 5.3.3 4a-d.
 */
static int resolve(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = kr_rplan_current(&req->rplan);
	if (!query || (query->flags & QUERY_RESOLVED)) {
		return ctx->state;
	}

	/* Check for packet processing errors first.
	 * Note - we *MUST* check if it has at least a QUESTION,
	 * otherwise it would crash on accessing QNAME. */
	if (pkt->parsed < pkt->size || pkt->parsed <= KNOT_WIRE_HEADER_SIZE) {
		DEBUG_MSG("<= malformed response\n");
		return resolve_badmsg(pkt, req, query);
	} else if (!is_paired_to_query(pkt, query)) {
		DEBUG_MSG("<= ignoring mismatching response\n");
		/* Force TCP, to work around authoritatives messing up question
		 * without yielding to spoofed responses. */
		query->flags |= QUERY_TCP;
		return resolve_badmsg(pkt, req, query);
	} else if (knot_wire_get_tc(pkt->wire)) {
		DEBUG_MSG("<= truncated response, failover to TCP\n");
		if (query) {
			/* Fail if already on TCP. */
			if (query->flags & QUERY_TCP) {
				DEBUG_MSG("<= TC=1 with TCP, bailing out\n");
				return resolve_error(pkt, req);
			}
			query->flags |= QUERY_TCP;
		}
		return KNOT_STATE_DONE;
	}

#ifdef WITH_DEBUG
	lookup_table_t *rcode = lookup_by_id(knot_rcode_names, knot_wire_get_rcode(pkt->wire));
#endif

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
	case KNOT_RCODE_REFUSED:
		break; /* OK */
	case KNOT_RCODE_FORMERR:
	case KNOT_RCODE_NOTIMPL:
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_badmsg(pkt, req, query);
	default:
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_error(pkt, req);
	}

	/* Resolve authority to see if it's referral or authoritative. */
	int state = KNOT_STATE_CONSUME;
	state = process_authority(pkt, req);
	switch(state) {
	case KNOT_STATE_CONSUME: /* Not referral, process answer. */
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		state = process_answer(pkt, req);
		break;
	case KNOT_STATE_DONE: /* Referral */
		DEBUG_MSG("<= referral response, follow\n");
		break;
	default:
		break;
	}

	return state;
}

/** Module implementation. */
const knot_layer_api_t *iterate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.reset = &reset,
		.finish = &finish,
		.consume = &resolve,
		.produce = &prepare_query
	};
	return &_layer;
}

KR_MODULE_EXPORT(iterate)
