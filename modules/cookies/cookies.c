/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

//#define PRINT_PACKETS 1 /* Comment out to disable packet printing. */

#include <assert.h>
#include <libknot/mm_ctx.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt_cookie.h> // branch dns-cookies-wip
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/module.h"
#include "lib/layer.h"

#define print_packet_dflt(pkt) do { } while(0)

#if defined(PRINT_PACKETS)
#include "print_pkt.h"

#undef print_packet_dflt
#define print_packet_dflt(pkt) print_packet((pkt), &DEFAULT_STYLE_DIG)
#endif /* PRINT_PACKETS */

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies",  fmt)

#define CLNT_SCRT_MIN 8 /* Minimum client secret size. */

/**
 * Holds the DNS cookies context.
 */
struct cookies_ctx {
	size_t clnt_scrt_size; /* Client secret size. */
	uint8_t *clnt_scrt; /* Client secret. */
};

/* Generates random client secret. */
static int clnt_scrt_create(struct cookies_ctx *ctx, unsigned int *seed)
{
	if (!ctx || !ctx->clnt_scrt || !seed) {
		return kr_error(EINVAL);
	}

	for (size_t i = 0; i < ctx->clnt_scrt_size; ++i) {
		ctx->clnt_scrt[i] = rand_r(seed) & 0xff;
	}

	return kr_ok();
}

/* Generates client cookie data. */
static int cc_data(const struct cookies_ctx *ctx,
                   uint8_t data[KNOT_OPT_COOKIE_CLNT])
{
	assert(data);

	/* TODO -- Currently we cannot obtain our IP address and are sure about
	 * the actual IP address of the server we are going to query. */

	if (!ctx || !ctx->clnt_scrt || ctx->clnt_scrt_size >= CLNT_SCRT_MIN) {
		return kr_error(EINVAL);
	}

	/* TODO -- We need to use a pseudo-random function to generate
	 * the client cookie. */

	assert(ctx->clnt_scrt_size >= KNOT_OPT_COOKIE_CLNT);
	memcpy(data, ctx->clnt_scrt, KNOT_OPT_COOKIE_CLNT);

	return kr_ok();
}

static int pkt_add_cookies(knot_pkt_t *pkt, struct cookies_ctx *ctx)
{
	uint16_t cookies_size = 0;
        uint8_t *cookies_data = NULL;

	uint8_t data[KNOT_OPT_COOKIE_CLNT];
	cc_data(ctx, data);

	if (!pkt->opt_rr) {
		pkt->opt_rr = mm_alloc(&pkt->mm, sizeof(knot_rrset_t));
		if (!pkt->opt_rr) {
			return kr_error(ENOMEM);
		}
		knot_edns_init(pkt->opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION,
		               &pkt->mm);
	}

	cookies_size = knot_edns_opt_cookie_data_len(0);

	int ret = knot_edns_reserve_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   cookies_size, &cookies_data,
	                                   &pkt->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(cookies_data != NULL);

	ret = knot_edns_opt_cookie_create(data, NULL, 0,
	                                  cookies_data, &cookies_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return kr_ok();
}

/* Process query. */
static int insert_cookie(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	DEBUG_MSG(NULL, "%s\n", "inserting client cookie into request");

	uint8_t data[KNOT_OPT_COOKIE_CLNT];

	struct kr_module *module = ctx->api->data;
	struct cookies_ctx *cookies_ctx = module->data;

	struct kr_request *req = ctx->data;
	/* req->answer contains EDNS data of primary request */
	struct kr_query *qry = req->current_query;

	if (kr_ok() != pkt_add_cookies(pkt, cookies_ctx)) {
		DEBUG_MSG(NULL, "%s\n", "Failed adding client cookie.");
	}

	print_packet_dflt(req->answer);
	DEBUG_MSG(NULL, "%s\n", "end inserting client cookie into request");

	return ctx->state;
}

/* Process response. */
static int check_response(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	DEBUG_MSG(NULL, "%s\n", "checking response");

	print_packet_dflt(pkt);

	return ctx->state;
}

/*
 * Module implementation.
 */

KR_EXPORT
const knot_layer_api_t *cookies_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
		.produce = &insert_cookie,
		.consume = &check_response
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int cookies_init(struct kr_module *module)
{
	struct cookies_ctx *data = malloc(sizeof(*data));
	if (!data) {
		return kr_error(ENOMEM);
	}
	data->clnt_scrt_size = CLNT_SCRT_MIN;
	data->clnt_scrt = malloc(data->clnt_scrt_size);
	if (!data->clnt_scrt) {
		return kr_error(ENOMEM);
	}

	unsigned int seed = time(NULL);
	clnt_scrt_create(data, &seed);

	module->data = data;
	return kr_ok();
}

KR_EXPORT
int cookies_deinit(struct kr_module *module)
{
	struct cookies_ctx *data = module->data;
	module->data = NULL;

	free(data->clnt_scrt);
	free(data);

	return kr_ok();
}

KR_EXPORT
struct kr_prop *cookies_props(void)
{
	static struct kr_prop prop_list[] = {
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(cookies);
