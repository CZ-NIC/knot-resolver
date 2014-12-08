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
#include <libknot/processing/requestor.h>
#include <libknot/dnssec/random.h>

#include "lib/layer/iterate.h"
#include "lib/rplan.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[qiter] " fmt, ## __VA_ARGS__)

static int cache_glue_rrs(knot_pkt_t *pkt, const knot_dname_t *ns_name, struct kr_context *resolve)
{
	int nr_stored = 0;
	struct kr_txn *txn = kr_context_txn_acquire(resolve, 0);

	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < ar->count; ++i) {
		if (!knot_dname_is_equal(ns_name, ar->rr[i].owner)) {
			continue;
		}
		if (kr_cache_insert(txn, &ar->rr[i], 0) != KNOT_EOK) {
			continue;
		}

		nr_stored += 1;
	}

	kr_context_txn_release(txn);
	return nr_stored;
}

static int plan_ns_resolution(struct kr_context *resolve, const knot_dname_t *ns_name)
{
#define TYPE_COUNT 2
	static const uint16_t type_list[TYPE_COUNT] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA };

	struct kr_txn *txn = kr_context_txn_acquire(resolve, KR_CACHE_RDONLY);
	knot_rrset_t cached_reply;
	knot_rrset_init(&cached_reply, (knot_dname_t *)ns_name, 0, KNOT_CLASS_IN);

	for (unsigned i = 0; i < TYPE_COUNT; ++i) {

		/* Check if type exists. */
		cached_reply.type = type_list[i];
		if (kr_cache_query(txn, &cached_reply) == 0) {
			knot_rdataset_clear(&cached_reply.rrs, resolve->pool);
			continue;
		}

		/* Plan query. */
		struct kr_query *qry = kr_rplan_push(&resolve->rplan, ns_name,
						     KNOT_CLASS_IN, type_list[i]);
		if (qry == NULL) {
			return KNOT_ENOMEM;
		}
		qry->flags  = RESOLVE_DELEG;

	}

	kr_context_txn_release(txn);

	return KNOT_EOK;
#undef TYPE_COUNT
}

static int inspect_authority_ns(const knot_rrset_t *ns_rr, knot_pkt_t *pkt, struct kr_context *resolve)
{
	/* Authority MUST be at/below the authority of the nameserver, otherwise
	 * possible cache injection attempt. */
	struct kr_zonecut *authority = resolve->zone_cut;
	if (!knot_dname_in(authority->name, ns_rr->owner)) {
		return KNOT_EMALF;
	}

	/* Fetch closest delegation point. */
	struct kr_zonecut *dp = kr_zonecut_get(&resolve->dp_map, ns_rr->owner);
	if (dp == NULL) {
		return KNOT_ENOMEM;
	}

	/* Create nameserver for this zone cut. */
	const knot_dname_t *ns_name = knot_ns_name(&ns_rr->rrs, 0);
	struct kr_ns *ns = kr_ns_get(&dp->nslist, ns_name, resolve->dp_map.pool);
	if (ns == NULL) {
		return KNOT_ENOMEM;
	}

	/* Cache glue records. */
	if (cache_glue_rrs(pkt, ns_name, resolve) < 1) {
		/* No glue record, attempt to resolve the nameserver */
		return plan_ns_resolution(resolve, ns_name);
	}

	return KNOT_EOK;
}

static int resolve_nonauth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		if (ns->rr[i].type != KNOT_RRTYPE_NS) {
			continue;
		}
		if (inspect_authority_ns(&ns->rr[i], pkt, param->ctx) != KNOT_EOK) {
			return KNOT_NS_PROC_FAIL;
		}
	}

	return KNOT_NS_PROC_DONE;
}

static void follow_cname_chain(const knot_dname_t **cname, const knot_rrset_t *rr,
                               struct kr_context *resolve)
{
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
static int update_query(knot_pkt_t *pkt, struct kr_layer_param *param, const knot_rrset_t *rr)
{
	struct kr_result *result = param->result;
	knot_pkt_t *ans = result->ans;
	knot_rrset_t *rr_copy = knot_rrset_copy(rr, &ans->mm);
	if (rr_copy == NULL) {
		return -1;
	}

	/* Write copied RR to the result packet. */
	int ret = knot_pkt_put(ans, KNOT_COMPR_HINT_NONE, rr_copy, KNOT_PF_FREE);
	if (ret != 0) {
		knot_rrset_free(&rr_copy, &ans->mm);
		knot_wire_set_tc(ans->wire);
	}

	/* Free just the allocated container. */
	mm_free(&ans->mm, rr_copy);

	return ret;
}

/*! \brief Result updates a delegation point. */
static int update_deleg(knot_pkt_t *pkt, struct kr_layer_param *param, const knot_rrset_t *rr)
{
	if (rr->type != KNOT_RRTYPE_NS) {
		return KNOT_EOK;
	}

	return inspect_authority_ns(rr, pkt, param->ctx);
}

static int update_result(knot_pkt_t *pkt, struct kr_query *cur, struct kr_layer_param *param, const knot_rrset_t *rr)
{
	int ret = KNOT_ERROR;

	/* RR callbacks per query type. */
	switch(cur->flags) {
	case RESOLVE_QUERY: ret = update_query(pkt, param, rr); break;
	case RESOLVE_DELEG: ret = update_deleg(pkt, param, rr); break;
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
		return KNOT_NS_PROC_FAIL;
	}

	/* Store flags. */
	knot_wire_set_rcode(ans->wire, knot_wire_get_rcode(pkt->wire));

	const knot_dname_t *cname = cur->sname;
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {

		/* RR callbacks per query type. */
		int ret = update_result(pkt, cur, param, &an->rr[i]);
		if (ret != KNOT_EOK) {
			return KNOT_NS_PROC_FAIL;
		}

		/* Update cache. */
		struct kr_txn *txn = kr_context_txn_acquire(resolve, 0);
		kr_cache_insert(txn, &an->rr[i], 0);
		kr_context_txn_release(txn);

		/* Check canonical name. */
		follow_cname_chain(&cname, &an->rr[i], resolve);
	}

	/* Follow canonical name as next SNAME. */
	if (cname != cur->sname) {
		struct kr_query *next = kr_rplan_push(&resolve->rplan, cname,
		                                      cur->sclass, cur->stype);
		if (next == NULL) {
			return KNOT_NS_PROC_FAIL;
		}
	}

	/* Resolved current SNAME. */
	resolve->resolved_qry = cur;

	return KNOT_NS_PROC_DONE;
}

/*! \brief Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	return KNOT_NS_PROC_FAIL;
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
static int reset(knot_layer_t *ctx)  { return KNOT_NS_PROC_FULL; }
static int finish(knot_layer_t *ctx) { return KNOT_NS_PROC_NOOP; }

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return reset(ctx);
}

static int prepare_query_cache(struct kr_query *next, struct kr_layer_param *param)
{
	int state = KNOT_NS_PROC_MORE;
	knot_rrset_t cached_reply;
	knot_rrset_init(&cached_reply, next->sname, next->stype, next->sclass);

	struct kr_context *resolve = param->ctx;
	struct kr_txn *txn = kr_context_txn_acquire(resolve, KR_CACHE_RDONLY);

	/* Try to find a CNAME/DNAME chain first. */
	bool found_hit = true;
	cached_reply.type = KNOT_RRTYPE_CNAME;
	if (kr_cache_query(txn, &cached_reply) != 0) {
		cached_reply.type = next->stype;
		if (kr_cache_query(txn, &cached_reply) != 0) {
			found_hit = false;
		}
	}

	/* Solve this from cache. */
	if (found_hit) {
		update_result(param->result->ans, next, param, &cached_reply);
		knot_wire_set_rcode(param->result->ans->wire, KNOT_RCODE_NOERROR);
		resolve->resolved_qry = next;
		state = KNOT_NS_PROC_DONE;

		/* Follow the CNAME chain. */
		if (cached_reply.type == KNOT_RRTYPE_CNAME) {
			const knot_dname_t *cname = next->sname;
			follow_cname_chain(&cname, &cached_reply, resolve);
			if (kr_rplan_push(&resolve->rplan, cname,next->sclass, next->stype) == NULL) {
				return KNOT_NS_PROC_FAIL;
			}
		}
	}
	kr_context_txn_release(txn);

	knot_rdataset_clear(&cached_reply.rrs, resolve->pool);
	return state;
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_context *resolve = param->ctx;
	struct kr_result *result = param->result;
	struct kr_query *next = kr_rplan_next(&resolve->rplan);
	if (next == NULL) {
		return KNOT_NS_PROC_FAIL;
	}

	/* Attempt to satisfy query form the cache. */
	int state = prepare_query_cache(next, param);
	if (state != KNOT_NS_PROC_MORE) {
		return state;
	}

	/* Form a query for the authoritative. */
	knot_pkt_clear(pkt);
	int ret = knot_pkt_put_question(pkt, next->sname, next->sclass, next->stype);
	if (ret != KNOT_EOK) {
		return KNOT_NS_PROC_FAIL;
	}

	knot_wire_set_id(pkt->wire, knot_random_uint16_t());

	/* Query built, expect answer. */
#ifndef NDEBUG
	char query_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_rrtype_to_string(next->stype, type_str, sizeof(type_str));
	knot_dname_to_str(query_str, next->sname, sizeof(query_str));
	DEBUG_MSG("query send '%s' type '%s'\n", query_str, type_str);
#endif

	result->nr_queries += 1;
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
