#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include "lib/resolve.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"

/* TODO: temporary */
#include <libknot/rrset-dump.h>
#include <common/print.h>

static void print_result(struct kr_result *result)
{
#ifndef NDEBUG
	char *qnamestr = knot_dname_to_str(knot_pkt_qname(result->ans));
	char *cnamestr = knot_dname_to_str(result->cname);
	printf("resolution of %s -> %s\n", qnamestr, cnamestr);
	free(qnamestr); free(cnamestr);

	printf("rcode = %d (%u RR)\n", knot_wire_get_rcode(result->ans->wire), result->ans->rrset_count);
	char strbuf[4096] = {0};
	int buflen = sizeof(strbuf);
	knot_dump_style_t style = {0};
	for (unsigned i = 0; i < result->ans->rrset_count; ++i) {
		int r = knot_rrset_txt_dump(&result->ans->rr[i], strbuf, buflen, &style);
		if (r > 0) buflen -= r;
	}

	printf("%s", strbuf);
	printf("queries: %u\n", result->nr_queries);
	printf("rtt %.02f msecs\n", time_diff(&result->t_start, &result->t_end));
#endif
}

static void iterate(struct knot_requestor *requestor, struct kr_context* ctx)
{
	struct timeval timeout = { 5, 0 };

	/* Find closest delegation point. */
	list_t *dp = kr_delegmap_find(&ctx->dp_map, ctx->sname);
	if (dp == NULL) {
		ctx->state = NS_PROC_FAIL;
		return;
	}

	struct kr_delegpt *ns = NULL;
	WALK_LIST(ns, *dp) {
		if (ns->flags & DP_RESOLVED) {
			break;
		}
		/* TODO: validity */
	}

	assert(ns->flags & DP_RESOLVED);

	/* Build query. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);

	/* Resolve. */
	struct knot_request *tx = knot_request_make(requestor->mm,
	                         (struct sockaddr *)&ns->addr,
	                         NULL, query, 0);
	knot_requestor_enqueue(requestor, tx);
	int ret = knot_requestor_exec(requestor, &timeout);
	if (ret != 0) {
		/* Move to the tail, and disable. */
		rem_node((node_t *)ns);
		add_tail(dp, (node_t *)ns);
		ns->flags = DP_LAME;
	}
}

int kr_resolve(struct kr_context* ctx, struct kr_result* result,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || result == NULL || qname == NULL) {
		return -1;
	}

	/* Initialize context. */
	ctx->sname = qname;
	ctx->sclass = qclass;
	ctx->stype = qtype;
	ctx->state = NS_PROC_MORE;
	ctx->query = NULL;
	kr_result_init(ctx, result);

	struct kr_layer_param param;
	param.ctx = ctx;
	param.result = result;

	/* Initialize requestor and overlay. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, ctx->pool);
	knot_requestor_overlay(&requestor, LAYER_STATIC, &param);
	knot_requestor_overlay(&requestor, LAYER_ITERATE, &param);
	while(ctx->state & (NS_PROC_MORE|NS_PROC_FULL)) {
		iterate(&requestor, ctx);
	}

	/* Clean up. */
	knot_requestor_clear(&requestor);

	print_result(result);

	return 0;
}
