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
#include <libknot/db/db_lmdb.h>
#include <libknot/error.h>
#include <libknot/mm_ctx.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt_cookie.h> // branch dns-cookies-wip
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "daemon/engine.h"
#include "lib/cookies/control.h"
#include "lib/module.h"
#include "lib/layer.h"

#define print_packet_dflt(pkt) do { } while(0)

#if defined(PRINT_PACKETS)
#include "print_pkt.h"

#undef print_packet_dflt
#define print_packet_dflt(pkt) print_packet((pkt), &DEFAULT_STYLE_DIG)
#endif /* PRINT_PACKETS */

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies",  fmt)

/**
 * Check whether supplied client cookie was generated from given client secret
 * and address.
 *
 * TODO -- The context must store sent cookies and server addresses in order
 * to make the process more reliable.
 */
static int check_client_cookie(const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                               void *clnt_sockaddr, void *srvr_sockaddr,
                               struct secret_quantity *secret)
{
	uint8_t generated_cc[KNOT_OPT_COOKIE_CLNT] = {0, };

	int ret = kr_client_cokie_fnv64(generated_cc, clnt_sockaddr,
	                                srvr_sockaddr, secret);
	if (ret != kr_ok()) {
		return ret;
	}

	ret = memcmp(cc, generated_cc, KNOT_OPT_COOKIE_CLNT);
	if (ret == 0) {
		return kr_ok();
	}

	return kr_error(EINVAL);
}

/** Process response. */
static int check_response(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	if (!kr_cookies_control.enabled) {
		return ctx->state;
	}

	if (!knot_pkt_has_edns(pkt)) {
		return ctx->state;
	}

	uint8_t *cookie_opt = knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE);
	if (!cookie_opt) {
		return ctx->state;
	}

	uint8_t *cookie_data = knot_edns_opt_get_data(cookie_opt);
	uint16_t cookie_len = knot_edns_opt_get_length(cookie_opt);
	assert(cookie_data && cookie_len);

	const uint8_t *cc = NULL, *sc = NULL;
	uint16_t cc_len = 0, sc_len = 0;

	int ret = knot_edns_opt_cookie_parse(cookie_data, cookie_len,
	                                     &cc, &cc_len, &sc, &sc_len);
	if (ret != KNOT_EOK) {
		DEBUG_MSG(NULL, "%s\n", "received malformed DNS cookie");
		/* TODO -- Generate error. */
		return ctx->state;
	}

	assert(cc_len == KNOT_OPT_COOKIE_CLNT);

	DEBUG_MSG(NULL, "%s\n", "checking response for received cookies");

	const void *srvr_sockaddr = NULL;

	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	struct kr_nsrep *ns = &qry->ns;

	/* Abusing name server reputation mechanism to obtain IP addresses. */
	for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
		if (ns->addr[i].ip.sa_family == AF_UNSPEC) {
			break;
		}
		ret = check_client_cookie(cc, NULL, &ns->addr[i], kr_cookies_control.client);
		WITH_DEBUG {
			char addr_str[INET6_ADDRSTRLEN];
			inet_ntop(ns->addr[i].ip.sa_family,
			          kr_nsrep_inaddr(ns->addr[i]), addr_str,
			          sizeof(addr_str));
			DEBUG_MSG(NULL, "nsrep address '%s' %d\n", addr_str, ret);
		}
		if (ret == kr_ok()) {
			srvr_sockaddr = &ns->addr[i];
			break;
		}
	}

	if (!srvr_sockaddr) {
		DEBUG_MSG(NULL, "%s\n",
		          "could not ensure any server for received cookie");
		/* TODO -- Generate error. */
		return ctx->state;
	}

	DEBUG_MSG(NULL, "%s\n", "caching server cookie");

	print_packet_dflt(pkt);

	return ctx->state;
}

/** Find storage API with given prefix. */
static struct storage_api *find_storage_api(const storage_registry_t *registry,
                                            const char *prefix)
{
	assert(registry);
	assert(prefix);

	for (unsigned i = 0; i < registry->len; ++i) {
		struct storage_api *storage = &registry->at[i];
		if (strcmp(storage->prefix, "lmdb://") == 0) {
			return storage;
		}
	}

	return NULL;
}

/*
 * Module implementation.
 */

KR_EXPORT
const knot_layer_api_t *cookies_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
		.consume = &check_response
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int cookies_init(struct kr_module *module)
{
	const char *storage_prefix = "lmdb://";
	struct engine *engine = module->data;
	DEBUG_MSG(NULL, "initialising with engine %p\n", (void *) engine);

	kr_cookies_control.enabled = true; /* Leave enabled by default. */
	memset(&kr_cookies_control.cache, 0, sizeof(kr_cookies_control.cache));

	struct storage_api *lmdb_storage_api = find_storage_api(&engine->storage_registry,
	                                                        storage_prefix);
	DEBUG_MSG(NULL, "found storage API %p for prefix '%s'\n",
	          (void *) lmdb_storage_api, storage_prefix);

	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = "cookies_db";
	//opts.dbname = "cookies";
	opts.mapsize = 1024 * 1024 * 1024;
	opts.maxdbs = 2;
	opts.flags.env = 0x80000 | 0x100000; /* MDB_WRITEMAP|MDB_MAPASYNC */

	errno = 0;
	int ret = kr_cache_open(&kr_cookies_control.cache,
	                        lmdb_storage_api->api(), &opts, engine->pool);
	DEBUG_MSG(NULL, "cache_open retval %d: %s\n", ret, kr_strerror(ret));

	module->data = NULL;

	return kr_ok();
}

KR_EXPORT
int cookies_deinit(struct kr_module *module)
{
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
