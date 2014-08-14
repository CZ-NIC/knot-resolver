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

static int evaluate_dp(const knot_rrset_t *dp, knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;

	/* Check if there's a glue for the record. */
	struct sockaddr_storage ss;
	const knot_dname_t *dp_name = knot_ns_name(&dp->rrs, 0);
	int ret = glue_record(pkt, dp_name, (struct sockaddr *)&ss);
	if (ret != 0) {
		/* TODO: lookup delegation if not provided in additionals */
		return -1;
	}

	/* Add delegation to the SLIST. */
	kr_slist_add(resolve, dp->owner, (struct sockaddr *)&ss);

	return 0;
}

static int resolve_nonauth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		if (ns->rr[i].type == KNOT_RRTYPE_NS) {
			evaluate_dp(&ns->rr[i], pkt, param);
		}
	}

	return NS_PROC_DONE;
}

static void follow_cname_chain(const knot_rrset_t *rr, struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;
	struct kr_result *result = param->result;

	/* Follow chain from SNAME. */
	if (knot_dname_is_equal(rr->owner, result->cname)) {
		if (rr->type == KNOT_RRTYPE_CNAME) {
			result->cname = knot_cname_name(&rr->rrs);
		} else {
			/* Terminate CNAME chain. */
			result->cname = resolve->sname;
		}
	}
}

static int resolve_auth(knot_pkt_t *pkt, struct kr_layer_param *param)
{
	struct kr_context *resolve = param->ctx;
	struct kr_result *result = param->result;
	knot_pkt_t *ans = result->ans;

	/* Store flags. */
	knot_wire_set_rcode(ans->wire, knot_wire_get_rcode(pkt->wire));

	/* Add results to the final packet. */
	/* TODO: API call */
	result->cname = resolve->sname;
	knot_pkt_begin(ans, KNOT_ANSWER);
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		knot_rrset_t *rr = knot_rrset_copy(&an->rr[i], &ans->mm);
		if (rr == NULL) {
			return NS_PROC_FAIL;
		}
		int ret = knot_pkt_put(ans, COMPR_HINT_NONE, rr, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_free(&rr, &ans->mm);
			knot_wire_set_tc(ans->wire);
			return NS_PROC_FAIL;
		}

		/* Check canonical name. */
		/* TODO: these may not come in order, queueing is needed. */
		follow_cname_chain(rr, param);
		/* Free just the allocated container. */
		mm_free(&ans->mm, rr);

	}

	/* Follow canonical name as next SNAME. */
	if (result->cname != resolve->sname) {
		/* Reset name server scoring for new SNAME. */
		resolve->sname = result->cname;
		resolve->state = NS_PROC_MORE;
		return NS_PROC_DONE;
	}

	/* Finished for the original SNAME. */
	resolve->state = NS_PROC_DONE;

	/* Store stats. */
	gettimeofday(&result->t_end, NULL);

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
	return knot_wire_get_id(resolve->query->wire) == knot_wire_get_id(answer->wire) &&
	       resolve->sclass  == knot_pkt_qclass(answer) &&
	       resolve->stype   == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(resolve->sname, knot_pkt_qname(answer));
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
	struct kr_context* resolve = param->ctx;

	resolve->query = pkt;
	knot_pkt_clear(pkt);

	int ret = knot_pkt_put_question(pkt, resolve->sname, resolve->sclass, resolve->stype);
	if (ret != KNOT_EOK) {
		assert(0);
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
