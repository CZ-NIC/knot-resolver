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
#include <ccan/json/json.h>
#include <libknot/db/db_lmdb.h>
#include <libknot/error.h>
#include <libknot/mm_ctx.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt_cookie.h> // branch dns-cookies-wip
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "daemon/engine.h"
#include "lib/cookies/cache.h"
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

/**
 * Tries to guess the name server address from the reputation mechanism.
 */
static const struct sockaddr *guess_server_addr(const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                                                struct kr_nsrep *nsrep,
                                                struct secret_quantity *secret)
{
	assert(cc && nsrep && secret);

	const struct sockaddr *sockaddr = NULL;

	/* Abusing name server reputation mechanism to obtain IP addresses. */
	for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
		if (nsrep->addr[i].ip.sa_family == AF_UNSPEC) {
			break;
		}
		int ret = check_client_cookie(cc, NULL, &nsrep->addr[i], secret);
		WITH_DEBUG {
			char addr_str[INET6_ADDRSTRLEN];
			inet_ntop(nsrep->addr[i].ip.sa_family,
			          kr_nsrep_inaddr(nsrep->addr[i]), addr_str,
			          sizeof(addr_str));
			DEBUG_MSG(NULL, "nsrep address '%s' %d\n", addr_str, ret);
		}
		if (ret == kr_ok()) {
			sockaddr = (struct sockaddr *) &nsrep->addr[i];
			break;
		}
	}

	return sockaddr;
}

static bool is_cookie_cached(struct kr_cache *cache,
                             const struct sockaddr *sockaddr,
                             uint8_t *cookie_opt)
{
	assert(cache && sockaddr && cookie_opt);

	const uint8_t *cached_cookie = NULL;
	uint32_t timestamp = 0;

	struct kr_cache_txn txn;
	kr_cache_txn_begin(&kr_cookies_control.cache, &txn, KNOT_DB_RDONLY);

	int ret = kr_cookie_cache_peek_cookie(&txn, sockaddr, &cached_cookie,
	                                      &timestamp);
	if (ret != kr_ok()) {
		/* Not cached or error. */
		kr_cache_txn_abort(&txn);
		return false;
	}
	assert(cached_cookie);

	uint16_t cookie_opt_size = knot_edns_opt_get_length(cookie_opt) + KNOT_EDNS_OPTION_HDRLEN;
	uint16_t cached_cookie_size = knot_edns_opt_get_length((uint8_t *) cached_cookie) + KNOT_EDNS_OPTION_HDRLEN;

	if (cookie_opt_size != cached_cookie_size) {
		kr_cache_txn_abort(&txn);
		return false;
	}

	bool equal = (memcmp(cookie_opt, cached_cookie, cookie_opt_size) == 0);

	kr_cache_txn_abort(&txn);
	return equal;
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

	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	struct kr_nsrep *ns = &qry->ns;

	uint8_t *cookie_opt = knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE);
	if (!cookie_opt) {
		/* Don't do anything if no cookies received.
		 * TODO -- If cookies expected then discard response. The
		 * interface must provide information about the IP address of
		 * the server. */
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
		return KNOT_STATE_FAIL;
	}

	assert(cc_len == KNOT_OPT_COOKIE_CLNT);

	DEBUG_MSG(NULL, "%s\n", "checking response for received cookies");

	const struct sockaddr *srvr_sockaddr = NULL;

	/* Abusing name server reputation mechanism to obtain IP addresses. */
	srvr_sockaddr = guess_server_addr(cc, ns,
	                                  kr_cookies_control.current_cs);
	bool returned_current = (srvr_sockaddr != NULL);
	if (!srvr_sockaddr && kr_cookies_control.recent_cs) {
		/* Try recent client secret to check obtained cookie. */
		srvr_sockaddr = guess_server_addr(cc, ns,
		                                  kr_cookies_control.recent_cs);
	}
	if (!srvr_sockaddr) {
		DEBUG_MSG(NULL, "%s\n", "could not match received cookie");
		return KNOT_STATE_FAIL;
	}

	/* Don't cache received cookies that don't match the current secret. */
	if (returned_current &&
	    !is_cookie_cached(&kr_cookies_control.cache, srvr_sockaddr,
	                      cookie_opt)) {
		DEBUG_MSG(NULL, "%s\n", "caching server cookie");

		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(&kr_cookies_control.cache, &txn, 0) != 0) {
			/* Could not acquire cache. */
			return ctx->state;
		}

		ret = kr_cookie_cache_insert_cookie(&txn, srvr_sockaddr,
		                                    cookie_opt,
		                                    qry->timestamp.tv_sec);
		if (ret != kr_ok()) {
			kr_cache_txn_abort(&txn);
		} else {
			DEBUG_MSG(NULL, "%s\n", "cookie_cached");
			kr_cache_txn_commit(&txn);
		}

	}

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

#define NAME_ENABLED "enabled"
#define NAME_CLIENT_SECRET "client_secret"

static bool aply_enabled(struct cookies_control *cntrl, const JsonNode *node)
{
	if (node->tag == JSON_BOOL) {
		cntrl->enabled = node->bool_;
		return true;
	}

	return false;
}

static struct secret_quantity *new_sq_str(const JsonNode *node)
{
	assert(node && node->tag == JSON_STRING);

	size_t len = strlen(node->string_);

	struct secret_quantity *sq = malloc(sizeof(*sq) + len);
	if (!sq) {
		return NULL;
	}
	sq->size = len;
	memcpy(sq->data, node->string_, len);

	return sq;
}

#define holds_char(x) ((x) >= 0 && (x) <= 255)

static struct secret_quantity *new_sq_array(const JsonNode *node)
{
	assert(node && node->tag == JSON_ARRAY);

	const JsonNode *element = NULL;
	size_t cnt = 0;
	json_foreach(element, node) {
		if (element->tag != JSON_NUMBER || !holds_char(element->number_)) {
			return NULL;
		}
		++cnt;
	}
	if (cnt == 0) {
		return NULL;
	}

	struct secret_quantity *sq = malloc(sizeof(*sq) + cnt);
	if (!sq) {
		return NULL;
	}

	sq->size = cnt;
	cnt = 0;
	json_foreach(element, node) {
		sq->data[cnt++] = (uint8_t) element->number_;
	}

	return sq;
}

static bool apply_client_secret(struct cookies_control *cntrl, const JsonNode *node)
{
	struct secret_quantity *sq = NULL;

	switch (node->tag) {
	case JSON_STRING:
		sq = new_sq_str(node);
		break;
	case JSON_ARRAY:
		sq = new_sq_array(node);
		break;
	default:
		break;
	}

	if (!sq) {
		return false;
	}

	if (sq->size == cntrl->current_cs->size &&
	    memcmp(sq->data, cntrl->current_cs->data, sq->size) == 0) {
		/* Ignore same values. */
		free(sq);
		return true;
	}

	struct secret_quantity *tmp = cntrl->recent_cs;
	cntrl->recent_cs = cntrl->current_cs;
	cntrl->current_cs = sq;

	if (tmp && tmp != &dflt_cs) {
		free(tmp);
	}

	return true;
}

static bool apply_configuration(struct cookies_control *cntrl, const JsonNode *node)
{
	assert(cntrl && node);

	if (!node->key) {
		/* All top most nodes must have names. */
		return false;
	}

	if (strcmp(node->key, NAME_ENABLED) == 0) {
		return aply_enabled(cntrl, node);
	} else if (strcmp(node->key, NAME_CLIENT_SECRET) == 0) {
		return apply_client_secret(cntrl, node);
	}

	return false;
}

static bool read_secret(JsonNode *root, struct cookies_control *cntrl)
{
	assert(root && cntrl);

	JsonNode *array = json_mkarray();
	if (!array) {
		return false;
	}

	for (size_t i = 0; i < cntrl->current_cs->size; ++i) {
		JsonNode *element = json_mknumber(cntrl->current_cs->data[i]);
		if (!element) {
			goto fail;
		}
		json_append_element(array, element);
	}

	json_append_member(root, NAME_CLIENT_SECRET, array);

	return true;

fail:
	if (array) {
		json_delete(array);
	}
	return false;
}

/**
 * Get/set DNS cookie related stuff.
 *
 * Input: { name: value, ... }
 * Output: current configuration
 */
static char *cookies_config(void *env, struct kr_module *module, const char *args)
{
	if (args && strlen(args) > 0) {
		JsonNode *node;
		JsonNode *root_node = json_decode(args);
		json_foreach (node, root_node) {
			apply_configuration(&kr_cookies_control, node);
		}
		json_delete(root_node);
	}

	/* Return current configuration. */
	char *result = NULL;
	JsonNode *root_node = json_mkobject();
	json_append_member(root_node, NAME_ENABLED, json_mkbool(kr_cookies_control.enabled));
	read_secret(root_node, &kr_cookies_control);
	result = json_encode(root_node);
	json_delete(root_node);
	return result;
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

	memset(&kr_cookies_control, 0, sizeof(kr_cookies_control));

	kr_cookies_control.enabled = false;

	kr_cookies_control.current_cs = &dflt_cs;

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
	kr_cookies_control.enabled = false;

	if (kr_cookies_control.recent_cs &&
	    kr_cookies_control.recent_cs != &dflt_cs) {
		free(kr_cookies_control.recent_cs);
	}
	kr_cookies_control.recent_cs = NULL;

	if (kr_cookies_control.current_cs &&
	    kr_cookies_control.current_cs != &dflt_cs) {
		free(kr_cookies_control.current_cs);
	}
	kr_cookies_control.current_cs = &dflt_cs;

	kr_cache_close(&kr_cookies_control.cache);

	return kr_ok();
}

KR_EXPORT
struct kr_prop *cookies_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &cookies_config, "config", "Empty value to return current configuration.", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(cookies);
