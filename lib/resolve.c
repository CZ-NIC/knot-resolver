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
} while(0)
#else
static void print_result(struct kr_result *result) {}
#define print_step
#endif

int kr_resolve(struct kr_context* ctx, struct kr_result* result,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || result == NULL || qname == NULL) {
		return -1;
	}

	ctx->sname = qname;
	ctx->sclass = qclass;
	ctx->stype = qtype;
	ctx->state = NS_PROC_MORE;
	kr_result_init(ctx, result);

	struct layer_param param;
	param.ctx = ctx;
	param.result = result;

	/* TODO: how to load all the layers? no API support yet */
	struct timeval timeout = { 5, 0 };
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, LAYER_ITERATE, ctx->pool);

	while(ctx->state != NS_PROC_DONE) {
		/* Sort preference list to the SNAME and pick a NS. */
		kr_slist_sort(ctx);
		struct kr_ns *ns = kr_slist_top(ctx);

		print_step("iterating");

		/* Resolve. */
		struct knot_request *tx = knot_requestor_make(&requestor,
		                         (const struct sockaddr *)&ns->addr,
		                         NULL, NULL, 0);
		knot_requestor_enqueue(&requestor, tx, &param);
		int ret = knot_requestor_exec(&requestor, &timeout);
		/* TODO: soft remove, retry later */
		if (ret != 0) {
			print_step("server failure %d", ret);
			kr_slist_pop(ctx);
		}
	}

	print_step(" ---> done");

	knot_requestor_clear(&requestor);

	print_result(result);

	return 0;
}
