/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sys/time.h>

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/aaaa.h>
#include <libknot/processing/requestor.h>
#include <libknot/dnssec/random.h>

#include "lib/layer/iterate.h"
#include "lib/rplan.h"

static int glue_record(knot_pkt_t *pkt, const knot_dname_t *dp, struct sockaddr *sa)
{
	/* TODO: API call for find() */
	const knot_rrset_t *glue_rr = NULL;
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < ar->count; ++i) {
		if (knot_dname_is_equal(dp, ar->rr[i].owner)) {
			glue_rr = &ar->rr[i];
			break;
		}
	}

	/* Delegation, without glue record. */
	if (glue_rr == NULL) {
		return -1;
	}

	/* Retrieve an address from glue record. */
	switch(glue_rr->type) {
	case KNOT_RRTYPE_A:
		knot_a_addr(&glue_rr->rrs, 0, (struct sockaddr_in *)sa);
		break;
	case KNOT_RRTYPE_AAAA:
		knot_aaaa_addr(&glue_rr->rrs, 0, (struct sockaddr_in6 *)sa);
		break;
	default:
		return -1;
	}

	sockaddr_port_set((struct sockaddr_storage *)sa, 53);
	return 0;
}

static int inspect_dp(const knot_rrset_t *ns_rr, knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;

	/* Fetch delegation point. */
	list_t *dp = kr_delegmap_get(&resolve->dp_map, ns_rr->owner);
	if (dp == NULL) {
		return -1;
	}

	const knot_dname_t *ns_name = knot_ns_name(&ns_rr->rrs, 0);
	struct kr_ns *ns = kr_ns_get(dp, ns_name, resolve->dp_map.pool);

	/* Update only unresolved NSs. */
	/* TODO: cache expiration */
	if (ns->flags & DP_RESOLVED) {
		return 0;
	}

	/* Check if there's a glue for the record. */
	int ret = glue_record(pkt, ns_name, (struct sockaddr *)&ns->addr);
	if (ret == 0) {
		ns->flags = DP_RESOLVED;
	} else {
		ns->flags = DP_LAME;
	}

	return 0;
}

static int resolve_nonauth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		if (ns->rr[i].type == KNOT_RRTYPE_NS) {
			inspect_dp(&ns->rr[i], pkt, param);
		}
	}

	return NS_PROC_DONE;
}

static void follow_cname_chain(const knot_dname_t **cname, const knot_rrset_t *rr,
                               struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;
	struct kr_query *cur = kr_rplan_next(&resolve->rplan);
	assert(cur);

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

/*! \brief Result updates the original query. */
static int update_query(struct kr_query *qry, struct kr_result *result, const knot_rrset_t *rr)
{
	knot_pkt_t *ans = result->ans;
	knot_rrset_t *rr_copy = knot_rrset_copy(rr, &ans->mm);
	if (rr_copy == NULL) {
		return -1;
	}

	/* Write copied RR to the result packet. */
	int ret = knot_pkt_put(ans, COMPR_HINT_NONE, rr_copy, KNOT_PF_FREE);
	if (ret != 0) {
		knot_rrset_free(&rr_copy, &ans->mm);
		knot_wire_set_tc(ans->wire);
	}

	/* Free just the allocated container. */
	mm_free(&ans->mm, rr_copy);

	return ret;
}

/*! \brief Result updates a delegation point. */
static int update_deleg(struct kr_query *qry, struct kr_result *result, const knot_rrset_t *rr)
{
	struct kr_ns *ns = qry->ext;

	if (ns->flags & DP_RESOLVED) {
		return 0;
	}

	if (!knot_dname_is_equal(ns->name, rr->owner)) {
		return 0;
	}

	/* Fetch address. */
	switch(rr->type) {
	case KNOT_RRTYPE_A:
		knot_a_addr(&rr->rrs, 0, (struct sockaddr_in *)&ns->addr);
		break;
	case KNOT_RRTYPE_AAAA:
		knot_aaaa_addr(&rr->rrs, 0, (struct sockaddr_in6 *)&ns->addr);
		break;
	default:
		return 0; /* Ignore unsupported RR type. */
	}

	/* Mark NS as resolved. */
	sockaddr_port_set(&ns->addr, 53);
	ns->flags = DP_RESOLVED;

	return 0;
}

static int update_result(struct kr_query *cur, struct kr_result *result, const knot_rrset_t *rr)
{
	int ret = -1;

	/* RR callbacks per query type. */
	switch(cur->flags) {
	case RESOLVE_QUERY: ret = update_query(cur, result, rr); break;
	case RESOLVE_DELEG: ret = update_deleg(cur, result, rr); break;
	default: assert(0); break;
	}

	return ret;
}

static int resolve_auth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;
	struct kr_result *result = param->result;
	knot_pkt_t *ans = result->ans;
	struct kr_query *cur = kr_rplan_next(&resolve->rplan);
	if (cur == NULL) {
		return NS_PROC_FAIL;
	}

	/* Store flags. */
	knot_wire_set_rcode(ans->wire, knot_wire_get_rcode(pkt->wire));

	const knot_dname_t *cname = cur->sname;
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {

		/* RR callbacks per query type. */
		int ret = update_result(cur, result, &an->rr[i]);
		if (ret != 0) {
			return NS_PROC_FAIL;
		}

		/* Update cache. */
		kr_cache_insert(result->txn, &an->rr[i], 0);

		/* Check canonical name. */
		follow_cname_chain(&cname, &an->rr[i], param);
	}

	/* Follow canonical name as next SNAME. */
	if (cname != cur->sname) {
		struct kr_query *next = kr_rplan_push(&resolve->rplan, cname,
		                                      cur->sclass, cur->stype);
		if (next == NULL) {
			return NS_PROC_FAIL;
		}
	}

	/* Resolved current SNAME. */
	resolve->resolved_qry = cur;

	return NS_PROC_DONE;
}

/*! \brief Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	return NS_PROC_FAIL;
}

/*! \brief Answer is paired to query. */
static bool is_answer_to_query(const knot_pkt_t *answer, struct kr_context *resolve)
{
	struct kr_query *expect = kr_rplan_next(&resolve->rplan);
	if (expect == NULL) {
		return -1;
	}

	return knot_wire_get_id(resolve->query->wire) == knot_wire_get_id(answer->wire) &&
	       expect->sclass  == knot_pkt_qclass(answer) &&
	       expect->stype   == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(expect->sname, knot_pkt_qname(answer));
}

/* State-less single resolution iteration step, not needed. */
static int reset(knot_layer_t *ctx)  { return NS_PROC_FULL; }
static int finish(knot_layer_t *ctx) { return NS_PROC_NOOP; }

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
	struct kr_context *resolve = param->ctx;
	struct kr_result *result = param->result;
	struct kr_query *next = kr_rplan_next(&resolve->rplan);
	if (next == NULL) {
		return -1;
	}

	/* TODO: hacked cache */
	knot_rrset_t cached_reply;
	knot_rrset_init(&cached_reply, next->sname, next->stype, next->sclass);
	if (kr_cache_query(result->txn, &cached_reply) == 0) {
		/* Solve this from cache. */
		update_result(next, result, &cached_reply);
		knot_rdataset_clear(&cached_reply.rrs, resolve->pool);

		/* Resolved current SNAME. */
		knot_wire_set_rcode(result->ans->wire, KNOT_RCODE_NOERROR);
		resolve->resolved_qry = next;
		return NS_PROC_DONE;
	}
	knot_rdataset_clear(&cached_reply.rrs, resolve->pool);

	knot_pkt_clear(pkt);

	int ret = knot_pkt_put_question(pkt, next->sname, next->sclass, next->stype);
	if (ret != KNOT_EOK) {
		return NS_PROC_FAIL;
	}

	knot_wire_set_id(pkt->wire, knot_random_uint16_t());

	/* Query complete, expect answer. */
	return NS_PROC_MORE;
}

/*! \brief Resolve input query or continue resolution with followups.
 *
 *  This roughly corresponds to RFC1034, 5.3.3 4a-d.
 */
static int resolve(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;

	/* Check for packet processing errors first. */
	if (pkt->parsed < pkt->size) {
		return resolve_error(pkt, param);
	}

	/* Is this the droid we're looking for? */
	if (!is_answer_to_query(pkt, param->ctx)) {
		return resolve_error(pkt, param);
	}

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	default:
		return resolve_error(pkt, param);
	}

	/* Is the answer delegation? */
	if (!knot_wire_get_aa(pkt->wire)) {
		return resolve_nonauth(pkt, param);
	}

	return resolve_auth(pkt, param);
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
