#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include "lib/resolve.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"

/* TODO: temporary */
#include <libknot/rrset-dump.h>
#include <common/print.h>

#ifndef NDEBUG
static void print_result(struct kr_result *result)
{
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
}

#define print_step(s...) \
do { \
	char *_qstr = knot_dname_to_str(ctx->sname); \
	char _astr[SOCKADDR_STRLEN]; \
	sockaddr_tostr(&kr_slist_top(ctx)->addr, _astr, sizeof(_astr)); \
	char *_soastr = knot_dname_to_str(kr_slist_top(ctx)->name); \
	printf("[%s] at %s (soa %s) ", _qstr, _astr, _soastr); \
	printf(s); \
	printf("\n"); \
	free(_qstr); \
	free(_soastr); \
} while(0)
#else
static void print_result(struct kr_result *result) {}
#define print_step
#endif

static void iterate(struct knot_requestor *requestor, struct kr_context* ctx)
{
	struct timeval timeout = { 5, 0 };

	/* Sort preference list to the SNAME and pick a NS. */
	kr_slist_sort(ctx);
	struct kr_ns *ns = kr_slist_top(ctx);
	if (ns == NULL) {
		ctx->state = NS_PROC_FAIL;
		return;
	}

	print_step("iterating");

	/* Build query. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);

	/* Resolve. */
	struct knot_request *tx = knot_request_make(requestor->mm,
	                         (const struct sockaddr *)&ns->addr,
	                         NULL, query, 0);
	knot_requestor_enqueue(requestor, tx);
	int ret = knot_requestor_exec(requestor, &timeout);
	/* TODO: soft remove, retry later */
	if (ret != 0) {
		print_step("server failure %d", ret);
		kr_slist_pop(ctx);
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

	while(ctx->state != NS_PROC_DONE) {
		iterate(&requestor, ctx);
	}

	/* Clean up. */

	knot_requestor_clear(&requestor);

	print_result(result);

	return 0;
}
