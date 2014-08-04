#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include "lib/resolve.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"

/* TODO: temporary */
#include <libknot/rrset-dump.h>

int kresolve_resolve(struct kresolve_ctx* ctx, struct kresolve_result* result,
                     const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	/* TODO: how to load all the layers? no API support yet */
	struct knot_requestor req;
	memset(result, 0, sizeof(struct kresolve_result));
	result->qname = qname;
	result->qclass = qclass;
	result->qtype = qtype;
	result->rcode = KNOT_RCODE_SERVFAIL;

	/* TODO: layer logic, where to? do one iteration step now */
	struct layer_iterate_param param;
	param.ctx = ctx;
	param.result = result;
	knot_requestor_init(&req, LAYER_ITERATE, ctx->mm);

	/* TODO: read root hints. */
	struct sockaddr_in root = uv_ip4_addr("198.41.0.4", 53);
	result->ns.name = NULL;
	memcpy(&result->ns.addr, &root, sizeof(root));

	/* Resolve. */
	ctx->state = NS_PROC_MORE;
	struct timeval tv = { 5, 0 };
	while (ctx->state == NS_PROC_MORE) {
		printf("execing\n");
		/* Create name resolution result structure and prepare first query. */
		knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MIN_PKTSIZE, ctx->mm);
		if (query == NULL) {
			return -1;
		}
		knot_pkt_put_question(query, qname, qclass, qtype);
		/* Check if the next address is valid. */
		struct knot_request *tx = knot_requestor_make(&req, &result->ns.addr, NULL, query);
		knot_requestor_enqueue(&req, tx, &param);
		knot_requestor_exec(&req, &tv);
		printf("exec'd\n");
	}
	knot_requestor_clear(&req);

	char *qnamestr = knot_dname_to_str(qname);
	char *cnamestr = knot_dname_to_str(result->cname);
	printf("resolution of %s -> %s\n", qnamestr, cnamestr);
	free(qnamestr); free(cnamestr);
	printf("rcode = %d (%u RR)\n", result->rcode, result->count);
	char strbuf[4096] = {0}; int buflen = sizeof(strbuf);
	knot_dump_style_t style = {0};
	for (unsigned i = 0; i < result->count; ++i) {
		int r = knot_rrset_txt_dump(result->data[i], strbuf, buflen, &style);
		if (r > 0) buflen -= r;
	}
	printf("%s\n", strbuf);

	return 0;
}
