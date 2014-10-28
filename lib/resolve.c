#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include <libknot/descriptor.h>
#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"
#include "lib/layer/stats.h"

static int resolve_ns(struct kr_context *resolve, struct kr_ns *ns)
{
	/* Create an address query. */
	struct kr_query *qry = kr_rplan_push(&resolve->rplan, ns->name,
	                                     KNOT_CLASS_IN, KNOT_RRTYPE_A);
	if (qry == NULL) {
		return -1;
	}

	/* Resolve as delegation. */
	qry->flags  = RESOLVE_DELEG;
	qry->ext    = ns;

	/* Mark as resolving. */
	ns->flags |= DP_PENDING;

	return 0;
}

static void iterate(struct knot_requestor *requestor, struct kr_context* ctx)
{
	struct timeval timeout = { KR_CONN_RTT_MAX / 1000, 0 };
	const struct kr_query *next = kr_rplan_next(&ctx->rplan);
	assert(next);

	/* Find closest delegation point. */
	list_t *dp = kr_delegmap_find(&ctx->dp_map, next->sname);
	if (dp == NULL) {
		ctx->state = KNOT_NS_PROC_FAIL;
		return;
	}

	struct kr_ns *ns = HEAD(*dp);
	if (!(ns->flags & DP_RESOLVED)) {

		/* Dependency loop or inaccessible resolvers, give up. */
		if (ns->flags & DP_PENDING) {
			ctx->state = KNOT_NS_PROC_FAIL;
			return;
		}

		resolve_ns(ctx, ns);
		return;
	}

	/* Update context. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	ctx->current_ns = ns;
	ctx->query = query;
	ctx->resolved_qry = NULL;

	/* Resolve. */
	struct knot_request *tx = knot_request_make(requestor->mm,
	                         (struct sockaddr *)&ns->addr,
	                         NULL, query, 0);
	knot_requestor_enqueue(requestor, tx);
	int ret = knot_requestor_exec(requestor, &timeout);
	if (ret != 0) {
		/* Resolution failed, invalidate current resolver. */
		kr_ns_invalidate(ns);
	}

	/* Pop resolved query. */
	if (ctx->resolved_qry) {
		kr_rplan_pop(&ctx->rplan, ctx->resolved_qry);
		ctx->resolved_qry = NULL;
	}

	/* Continue resolution if has more queries planned. */
	if (kr_rplan_next(&ctx->rplan) == NULL) {
		ctx->state = KNOT_NS_PROC_DONE;
	} else {
		ctx->state = KNOT_NS_PROC_MORE;
	}
}

int kr_resolve(struct kr_context* ctx, struct kr_result* result,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || result == NULL || qname == NULL) {
		return -1;
	}

	/* Initialize context. */
	ctx->state = KNOT_NS_PROC_MORE;
	kr_rplan_push(&ctx->rplan, qname, qclass, qtype);
	kr_result_init(ctx, result);

	struct kr_layer_param param;
	param.ctx = ctx;
	param.result = result;

	/* Initialize requestor and overlay. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, ctx->pool);
	knot_requestor_overlay(&requestor, LAYER_STATIC, &param);
	knot_requestor_overlay(&requestor, LAYER_ITERATE, &param);
	knot_requestor_overlay(&requestor, LAYER_STATS, &param);
	while(ctx->state & (KNOT_NS_PROC_MORE|KNOT_NS_PROC_FULL)) {
		iterate(&requestor, ctx);
	}

	/* Clean up. */
	knot_requestor_clear(&requestor);

	return 0;
}
