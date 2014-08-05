#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include "lib/resolve.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"

/* TODO: temporary */
#include <libknot/rrset-dump.h>
#include <common/print.h>

int kr_resolve(struct kr_context* ctx, struct kr_result* result,
                     const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	/* TODO: how to load all the layers? no API support yet */
	ctx->sname = knot_dname_copy(qname, ctx->mm);
	ctx->sclass = qclass;
	ctx->stype = qtype;
	kr_result_init(ctx, result);

	struct layer_param param;
	param.ctx = ctx;
	param.result = result;

	/* TODO: read root hints. */
	struct sockaddr_in root_addr = uv_ip4_addr("198.41.0.4", 53);
	kr_slist_add(ctx, knot_dname_copy((const uint8_t *)"", NULL), (struct sockaddr *)&root_addr);

	/* Resolve. */
	struct knot_requestor req;
	knot_requestor_init(&req, LAYER_ITERATE, ctx->mm);
	struct timeval tv = { 5, 0 };
	struct kr_ns *ns = NULL;
	struct knot_request *tx = NULL;
	int watchdog = 0;
	while(ctx->state != NS_PROC_DONE) {
		ns = kr_slist_top(ctx);
		tx = knot_requestor_make(&req, (const struct sockaddr *)&ns->addr,
		                         NULL, NULL);
		knot_requestor_enqueue(&req, tx, &param);
		knot_requestor_exec(&req, &tv);

		/* TODO: restart if sname != originating */
		if (qname != ctx->sname) {
			printf("we didn't resolve the cname target...yet\n");
		}

		/* TODO: safety check, remove */
		assert(++watchdog < 10);
	}
	knot_requestor_clear(&req);

	char *qnamestr = knot_dname_to_str(qname);
	char *cnamestr = knot_dname_to_str(ctx->sname);
	printf("resolution of %s -> %s\n", qnamestr, cnamestr);
	free(qnamestr); free(cnamestr);
	printf("rcode = %d (%u RR)\n", knot_wire_get_rcode(result->ans->wire), result->ans->rrset_count);
	char strbuf[4096] = {0}; int buflen = sizeof(strbuf);
	knot_dump_style_t style = {0};
	for (unsigned i = 0; i < result->ans->rrset_count; ++i) {
		int r = knot_rrset_txt_dump(&result->ans->rr[i], strbuf, buflen, &style);
		if (r > 0) buflen -= r;
	}
	printf("%s", strbuf);
	printf("queries: %u\n", result->nr_queries);
	printf("rtt %.02f msecs\n", time_diff(&result->t_start, &result->t_end));

	return 0;
}
