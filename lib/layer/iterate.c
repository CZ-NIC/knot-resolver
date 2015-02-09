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
#include <libknot/processing/requestor.h>
#include <libknot/dnssec/random.h>

#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"

#ifndef NDEBUG
#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[qiter] " fmt, ## __VA_ARGS__)
#else
#define DEBUG_MSG(fmt, ...)
#endif

/* Iterator often walks through packet section, this is an abstraction. */
typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_layer_param *);

/*! \brief Return minimized QNAME/QTYPE for current zone cut. */
static const knot_dname_t *minimized_qname(struct kr_query *query, uint16_t *qtype)
{
	/* Minimization disabled. */
	const knot_dname_t *qname = query->sname;
	if (query->flags & QUERY_NO_MINIMIZE) {
		return qname;
	}

	/* Minimize name to contain current zone cut + 1 label. */
	int cut_labels = knot_dname_labels(query->zone_cut.name, NULL);
	int qname_labels = knot_dname_labels(qname, NULL);
	while(qname_labels > cut_labels + 1) {
		qname = knot_wire_next_label(qname, NULL);
		qname_labels -= 1;
	}

	/* Hide QTYPE if minimized. */
	if (qname != query->sname) {
		*qtype = KNOT_RRTYPE_NS;
	}

	return qname;
}

/*! \brief Answer is paired to query. */
static bool is_paired_to_query(const knot_pkt_t *answer, struct kr_query *query)
{
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	return query->id      == knot_wire_get_id(answer->wire) &&
	       (query->sclass == KNOT_CLASS_ANY || query->sclass  == knot_pkt_qclass(answer)) &&
	       qtype          == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(qname, knot_pkt_qname(answer));
}

static void follow_cname_chain(const knot_dname_t **cname, const knot_rrset_t *rr,
                               struct kr_query *cur)
{
	/* Follow chain from SNAME. */
	if (knot_dname_is_equal(rr->owner, *cname)) {
		if (rr->type == KNOT_RRTYPE_CNAME) {
			*cname = knot_cname_name(&rr->rrs);
		} else {
			/* Terminate CNAME chain. */
			*cname = cur->sname;
		}
	}
}

static int update_nsaddr(const knot_rrset_t *rr, struct kr_query *query, uint16_t index)
{
	if (rr == NULL || query == NULL) {
		return KNOT_NS_PROC_MORE; /* Ignore */
	}

	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		if (knot_dname_is_equal(query->zone_cut.ns, rr->owner)) {
			int ret = kr_set_zone_cut_addr(&query->zone_cut, rr, index);
			if (ret == KNOT_EOK) {
				return KNOT_NS_PROC_DONE;
			}
		}
	}

	return KNOT_NS_PROC_MORE;
}

static int update_glue(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param)
{
	return update_nsaddr(rr, kr_rplan_current(param->rplan), hint);
}

int rr_update_parent(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param)
{
	struct kr_query *query = kr_rplan_current(param->rplan);
	return update_nsaddr(rr, query->parent, hint);
}

int rr_update_answer(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param)
{
	knot_pkt_t *answer = param->answer;
	
	/* Write copied RR to the result packet. */
	int ret = knot_pkt_put(answer, KNOT_COMPR_HINT_NONE, rr, hint);
	if (ret != KNOT_EOK) {
		if (hint & KNOT_PF_FREE) {
			knot_rrset_clear((knot_rrset_t *)rr, &answer->mm);
		}
		knot_wire_set_tc(answer->wire);
		return KNOT_NS_PROC_DONE;
	}

	/* Update parent query as well. */
	return rr_update_parent(rr, hint, param);
}

int rr_update_nameserver(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param)
{
	struct kr_query *query = kr_rplan_current(param->rplan);
	const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, hint);

	/* Authority MUST be at/below the authority of the nameserver, otherwise
	 * possible cache injection attempt. */
	if (!knot_dname_in(query->zone_cut.name, rr->owner)) {
		DEBUG_MSG("NS in query outside of its authority => rejecting\n");
		return KNOT_NS_PROC_FAIL;
	}

	/* Ignore already resolved zone cut. */
	if (knot_dname_is_equal(rr->owner, query->zone_cut.name)) {
		return KNOT_NS_PROC_MORE;
	}

	/* Set zone cut to given name server. */
	kr_set_zone_cut(&query->zone_cut, rr->owner, ns_name);
	return KNOT_NS_PROC_DONE;
}

static int process_authority(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	int state = KNOT_NS_PROC_MORE;

	/* Answer declares AA, can't be referral. */
	if (knot_wire_get_aa(pkt->wire)) {
		return state;
	}

	/* Update current zone cut from NS records. */
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		state = rr_update_nameserver(rr, 0, param);
		if (state != KNOT_NS_PROC_MORE) {
			break;
		}
	}

	return state;
}

static int process_additional(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_query *query = kr_rplan_current(param->rplan);

	/* Attempt to find glue for current nameserver. */
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < ar->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ar, i);
		int state = update_glue(rr, 0, param);
		if (state != KNOT_NS_PROC_MORE) {
			return state;
		}
	}

	/* Glue not found => resolve NS address. */
	(void) kr_rplan_push(param->rplan, query, query->zone_cut.ns, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA);
	(void) kr_rplan_push(param->rplan, query, query->zone_cut.ns, KNOT_CLASS_IN, KNOT_RRTYPE_A);

	return KNOT_NS_PROC_DONE;
}

static int process_answer(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_query *query = kr_rplan_current(param->rplan);

	/* Response for minimized QNAME.
	 * NODATA   => may be empty non-terminal, retry (found zone cut)
	 * NOERROR  => found zone cut, retry
	 * NXDOMAIN => parent is zone cut, retry as a workaround for bad authoritatives
	 */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	bool is_minimized = (!knot_dname_is_equal(knot_pkt_qname(pkt), query->sname));
	bool is_nodata = (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NOERROR) && !an->count;
	bool is_nxdomain = (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN);
	if (is_minimized && (is_nodata || is_nxdomain)) {
		query->flags |= QUERY_NO_MINIMIZE;
		return KNOT_NS_PROC_DONE;
	}

	/* Does this answer update the final response? */
	rr_callback_t callback = &rr_update_parent;
	if (query->parent == NULL) {
		knot_wire_set_rcode(param->answer->wire, knot_wire_get_rcode(pkt->wire));
		callback = &rr_update_answer;
	}

	/* Process answer section records. */
	const knot_dname_t *cname = query->sname;
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		int state = callback(rr, 0, param);
		if (state == KNOT_NS_PROC_FAIL) {
			return state;
		}
		follow_cname_chain(&cname, rr, query);
	}

	/* Follow canonical name as next SNAME. */
	if (cname != query->sname) {
		(void) kr_rplan_push(param->rplan, query->parent, cname, query->sclass, query->stype);
	}

	/* This is either declares AA or not, either way it resolves current query. */
	kr_rplan_pop(param->rplan, query);

	return KNOT_NS_PROC_DONE;
}

/*! \brief Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_layer_param *param, int errcode)
{
	DEBUG_MSG("resolution error => %s\n", knot_strerror(errcode));
	return KNOT_NS_PROC_FAIL;
}

/* State-less single resolution iteration step, not needed. */
static int reset(knot_layer_t *ctx)  { return KNOT_NS_PROC_FULL; }
static int finish(knot_layer_t *ctx) { return KNOT_NS_PROC_NOOP; }

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return reset(ctx);
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_query *query = kr_rplan_current(param->rplan);
	if (query == NULL || ctx->state == KNOT_NS_PROC_DONE) {
		return ctx->state;
	}

	/* Minimize QNAME (if possible). */
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	/* Form a query for the authoritative. */
	knot_pkt_clear(pkt);
	int ret = knot_pkt_put_question(pkt, qname, query->sclass, qtype);
	if (ret != KNOT_EOK) {
		return KNOT_NS_PROC_FAIL;
	}

	query->id = knot_random_uint16_t();
	knot_wire_set_id(pkt->wire, query->id);
	
	/* Declare EDNS0 support. */
	knot_rrset_t opt_rr;
	ret = knot_edns_init(&opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, &pkt->mm);
	if (ret != KNOT_EOK) {
		return KNOT_NS_PROC_FAIL;
	}

	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return KNOT_NS_PROC_FAIL;
	}

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(ns_str, query->zone_cut.ns, sizeof(ns_str));
	knot_dname_to_str(zonecut_str, query->zone_cut.name, sizeof(zonecut_str));
	knot_dname_to_str(name_str, qname, sizeof(name_str));
	knot_rrtype_to_string(qtype, type_str, sizeof(type_str));
	DEBUG_MSG("query '%s %s' zone cut '%s' nameserver '%s'\n", name_str, type_str, zonecut_str, ns_str);
#endif

	/* Query built, expect answer. */
	return KNOT_NS_PROC_MORE;
}

/*! \brief Resolve input query or continue resolution with followups.
 *
 *  This roughly corresponds to RFC1034, 5.3.3 4a-d.
 */
static int resolve(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_query *query = kr_rplan_current(param->rplan);
	if (query == NULL) {
		return ctx->state;
	}

	/* Check for packet processing errors first. */
	if (pkt->parsed < pkt->size) {
		return resolve_error(pkt, param, KNOT_EMALF);
	} else if (!is_paired_to_query(pkt, query)) {
		DEBUG_MSG("ignoring mismatching response\n");
		return KNOT_NS_PROC_MORE;
	} else if (knot_wire_get_tc(pkt->wire)) {
		DEBUG_MSG("truncated response, failover to TCP\n");
		struct kr_query *cur = kr_rplan_current(param->rplan);
		if (cur) {
			/* Fail if already on TCP. */
			if (cur->flags & QUERY_TCP) {
				return resolve_error(pkt, param, KNOT_EMALF);
			}
			cur->flags |= QUERY_TCP;
		}
		return KNOT_NS_PROC_DONE;
	}

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	default:
		return resolve_error(pkt, param, KNOT_ERROR);
	}

	/* Resolve authority to see if it's referral or authoritative. */
	int state = KNOT_NS_PROC_MORE;
	state = process_authority(pkt, param);
	switch(state) {
	case KNOT_NS_PROC_MORE: /* Not referral, process answer. */
		state = process_answer(pkt, param);
		break;
	case KNOT_NS_PROC_DONE: /* Referral, try to find glue. */
		state = process_additional(pkt, param);
		break;
	default:
		break;
	}

	return state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_ITERATE_MODULE = {
	&begin,
	&reset,
	&finish,
	&resolve,
	&prepare_query,
	NULL
};

const knot_layer_api_t *layer_iterate_module(void)
{
	return &LAYER_ITERATE_MODULE;
}
