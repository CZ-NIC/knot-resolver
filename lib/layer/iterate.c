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
#include "lib/utils.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[qiter] " fmt, ## __VA_ARGS__)

/*! \brief Fetch NS record address from additionals. */
static int glue_ns_addr(const knot_pkt_t *pkt, struct sockaddr_storage *addr, const knot_dname_t *name, uint16_t type)
{
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < ar->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ar, i);
		if (rr->type == type && knot_dname_is_equal(name, rr->owner)) {
			return kr_rrset_to_addr(addr, rr);
		}
	}

	return KNOT_ENOENT;
}

static int set_zone_cut(struct kr_rplan *rplan, knot_pkt_t *pkt, const knot_rrset_t *rr)
{
	static const uint16_t type_list[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA };

	/* Set zone cut to given name server. */
	const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, 0);
	kr_set_zone_cut(&rplan->zone_cut, rr->owner, ns_name);

	/* Check if we can find a valid address in glue / cache */
	for (unsigned i = 0; i < sizeof(type_list)/sizeof(uint16_t); ++i) {

		/* Find address in the additionals (optional). */
		int ret = glue_ns_addr(pkt, &rplan->zone_cut.addr, ns_name, type_list[i]);
		if (ret == KNOT_EOK) {
			return KNOT_EOK;
		}
	}

	/* Query for address records (if not glue). */
	for (unsigned i = 0; i < sizeof(type_list)/sizeof(uint16_t); ++i) {
		(void) kr_rplan_push(rplan, rplan->zone_cut.ns, KNOT_CLASS_IN, type_list[i]);
	}

	return KNOT_EOK;
}

static int inspect_ns(const knot_rrset_t *ns_rr, knot_pkt_t *pkt, struct kr_layer_param *param)
{
	/* Authority MUST be at/below the authority of the nameserver, otherwise
	 * possible cache injection attempt. */
	if (!knot_dname_in(param->rplan->zone_cut.name, ns_rr->owner)) {
		DEBUG_MSG("NS in query outside of its authority => rejecting\n");
		return KNOT_EMALF;
	}

	return KNOT_EOK;
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

/*! \brief Result updates the original query response. */
static int update_answer(knot_pkt_t *answer, const knot_rrset_t *rr)
{
	knot_rrset_t *rr_copy = knot_rrset_copy(rr, &answer->mm);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}

	/* Write copied RR to the result packet. */
	int ret = knot_pkt_put(answer, KNOT_COMPR_HINT_NONE, rr_copy, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rr_copy, &answer->mm);
		knot_wire_set_tc(answer->wire);
	}

	/* Free just the allocated container. */
	mm_free(&answer->mm, rr_copy);
	return KNOT_EOK;
}

static void update_zone_cut(struct kr_rplan *rplan, const knot_rrset_t *rr)
{
	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		if (knot_dname_is_equal(rplan->zone_cut.ns, rr->owner)) {
			kr_rrset_to_addr(&rplan->zone_cut.addr, rr);
		}
	}
}

static int resolve_referral(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	bool have_first_ns = false;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}
		/* Check each nameserver. */
		if (inspect_ns(rr, pkt, param) != KNOT_EOK) {
			return KNOT_NS_PROC_FAIL;
		}
		/* Resolve the first nameserver address, rest will be cached. */
		if (!have_first_ns) {
			set_zone_cut(param->rplan, pkt, rr);
			have_first_ns = true;
		}
	}

	return KNOT_NS_PROC_DONE;
}

static int resolve_auth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	knot_pkt_t *answer = param->answer;
	struct kr_query *cur = kr_rplan_current(param->rplan);
	if (cur == NULL) {
		return KNOT_NS_PROC_FAIL;
	}

	/* Is relevant for original query? */
	bool update_orig_answer = (cur == kr_rplan_last(param->rplan));

	const knot_dname_t *cname = cur->sname;
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);

		/* Update original answer or current zone cut. */
		if (update_orig_answer) {
			if (update_answer(answer, rr) != KNOT_EOK) {
				return KNOT_NS_PROC_FAIL;
			}
		} else {
			update_zone_cut(param->rplan, rr);
		}

		/* Check canonical name. */
		follow_cname_chain(&cname, rr, cur);
	}

	/* Follow canonical name as next SNAME. */
	if (cname != cur->sname) {
		struct kr_query *next = kr_rplan_push(param->rplan, cname,
		                                      cur->sclass, cur->stype);
		if (next == NULL) {
			return KNOT_NS_PROC_FAIL;
		}
	}

	/* Authoritative answer to original response => DONE. */
	if (update_orig_answer) {
		knot_wire_set_rcode(answer->wire, knot_wire_get_rcode(pkt->wire));
	}

	kr_rplan_pop(param->rplan, cur);
	return KNOT_NS_PROC_DONE;
}

/*! \brief Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_layer_param *param, int errcode)
{
	DEBUG_MSG("resolution error => %s\n", knot_strerror(errcode));
	return KNOT_NS_PROC_FAIL;
}

/*! \brief Answer is paired to query. */
static bool is_answer_to_query(const knot_pkt_t *answer, struct kr_rplan *rplan)
{
	struct kr_query *expect = kr_rplan_current(rplan);
	if (expect == NULL) {
		return -1;
	}

	return expect->id      == knot_wire_get_id(answer->wire) &&
	       expect->sclass  == knot_pkt_qclass(answer) &&
	       expect->stype   == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(expect->sname, knot_pkt_qname(answer));
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
	struct kr_query *cur = kr_rplan_current(param->rplan);
	if (cur == NULL || ctx->state == KNOT_NS_PROC_DONE) {
		return ctx->state;
	}

	/* Form a query for the authoritative. */
	knot_pkt_clear(pkt);
	int ret = knot_pkt_put_question(pkt, cur->sname, cur->sclass, cur->stype);
	if (ret != KNOT_EOK) {
		return KNOT_NS_PROC_FAIL;
	}

	cur->id = knot_random_uint16_t();
	knot_wire_set_id(pkt->wire, cur->id);

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(name_str, param->rplan->zone_cut.ns, sizeof(name_str));
	DEBUG_MSG("sending query to %s\n", name_str);
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
	int state = ctx->state;

	/* Check for packet processing errors first. */
	if (pkt->parsed < pkt->size) {
		return resolve_error(pkt, param, KNOT_EMALF);
	}

	/* Is this the droid we're looking for? */
	if (!is_answer_to_query(pkt, param->rplan)) {
		DEBUG_MSG("ignoring mismatching response\n");
		return KNOT_NS_PROC_MORE;
	}

	/* TODO: classify response type
	 * 1. authoritative, noerror/nxdomain
	 *     cname chain => update current sname
	 *     qname is current ns => update ns address
	 *     qname is tail => original query
	 * 2. referral, update current zone cut
	 */

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	default:
		return resolve_error(pkt, param, KNOT_ERROR);
	}

	/* Is the answer authoritative? */
	if (knot_wire_get_aa(pkt->wire)) {
		state = resolve_auth(pkt, param);
	} else {
		state = resolve_referral(pkt, param);
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
