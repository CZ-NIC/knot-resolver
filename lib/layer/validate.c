/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <sys/time.h>

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>

#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(&req->rplan), "validate", fmt)

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
#warning TODO: set root trust anchor
	ctx->data = module_param;
	return KNOT_STATE_PRODUCE;
}

static int secure_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = kr_rplan_current(&req->rplan);
	if (ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}

	/* Copy query EDNS options and request DNSKEY for current cut. */
	pkt->opt_rr = knot_rrset_copy(req->answer->opt_rr, &pkt->mm);
	query->flags |= QUERY_AWAIT_TRUST;
#warning TODO: check if we already have valid DNSKEY in zone cut, otherwise request it from the resolver
#warning FLOW: since first query doesnt have it, resolve.c will catch this and issue subrequest for it
	/* Write OPT to additional section */
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);

	return KNOT_STATE_CONSUME;
}

static int validate(knot_layer_t *ctx, knot_pkt_t *pkt)
{
#warning TODO: check if we have DNSKEY in qry->zone_cut and validate RRSIGS/proof, return FAIL if failed
#warning TODO: we must also validate incoming DNSKEY records against the current zone cut TA
#warning FLOW: first answer that comes here must have the DNSKEY that we can validate using TA
}

/** Module implementation. */
const knot_layer_api_t *validate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.consume = &validate,
		.produce = &secure_query
	};
	return &_layer;
}

KR_MODULE_EXPORT(validate)
