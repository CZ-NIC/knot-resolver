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

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/layer/iterate.h"

/* State-less single resolution iteration step, not needed. */
static int reset(knot_process_t *ctx)  { return NS_PROC_MORE; }
static int finish(knot_process_t *ctx) { return NS_PROC_NOOP; }

/* Set resolution context and parameters. */
static int begin(knot_process_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return NS_PROC_MORE;
}

/* Resolve input query or continue resolution with followups. */
static int resolve(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct layer_iterate_param *param = ctx->data;

	struct kresolve_ctx *resolution = param->ctx;
	struct kresolve_result *result = param->result;

	/* Is the answer authoritative? */
	bool is_aa = knot_wire_get_aa(pkt->wire);
	printf("got packet: AA? %d RRs %d RCODE %d\n", is_aa, pkt->rrset_count, knot_wire_get_rcode(pkt->wire));
	if (is_aa) {
		/* Add results to the answer section. */
		const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
		for (unsigned i = 0; i < an->count; ++i) {
			knot_rrset_t *copy = knot_rrset_copy(an->rr + i, resolution->mm);
			result->data[result->count] = copy;
			result->count += 1;
		}
		/* Store canonical name. */
		result->cname = knot_dname_copy(knot_pkt_qname(pkt), resolution->mm);
		/* TODO: store flags */
		/* Finished. */
		resolution->state = NS_PROC_DONE;
	} else {
		/* Is there a NS to add into SLIST? */
		knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
		result->ns.name = NULL;
		memset(&result->ns.addr, 0, sizeof(result->ns.addr));
		for (unsigned i = 0; i < ns->count; ++i) {
			if (ns->rr[i].type == KNOT_RRTYPE_NS) {
				result->ns.name = knot_ns_name(&ns->rr[i].rrs, 0);
				/* TODO: fill SLIST */
				printf("next nameserver: %s\n", knot_dname_to_str(result->ns.name));
				break;
			}
		}

		/* No next nameserver? */
		if (result->ns.name == NULL) {
			printf("no next nameserver\n");
			resolution->state = NS_PROC_FAIL;
			return NS_PROC_FAIL;
		}

		/* Is the address in additional records? */
		knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
		for (unsigned i = 0; i < ar->count; ++i) {
			printf("checking additional: %s type %d\n", knot_dname_to_str(ar->rr[i].owner), ar->rr[i].type);
			if (knot_dname_is_equal(result->ns.name, ar->rr[i].owner)) {

				/* Fill next server address. */
				switch(ar->rr[i].type) {
				case KNOT_RRTYPE_A:
					knot_a_addr(&ar->rr[i].rrs, 0, &result->ns.addr);
					break;
				case KNOT_RRTYPE_AAAA:
					knot_aaaa_addr(&ar->rr[i].rrs, 0, &result->ns.addr);
					break;
				default:
					resolution->state = NS_PROC_FAIL;
					return NS_PROC_FAIL;
				}

				/* Fill port. */
				sockaddr_port_set(&result->ns.addr, 53);

				break;
			}
		}

		char tmpbuf[512];
		sockaddr_tostr(&result->ns.addr, tmpbuf, 512);
		printf("next addr: %s\n", tmpbuf);
	}

	printf("done\n");

	return NS_PROC_DONE;
}

/*! \brief Module implementation. */
static const knot_process_module_t LAYER_ITERATE_MODULE = {
	&begin,
	&reset,
	&finish,
	&resolve,
	&knot_process_noop, /* No output. */
	&knot_process_noop  /* No error processing. */
};

const knot_process_module_t *layer_iterate_module(void)
{
	return &LAYER_ITERATE_MODULE;
}
