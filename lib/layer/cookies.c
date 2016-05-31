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

#include <assert.h>
#include <ccan/json/json.h>
#include <libknot/db/db_lmdb.h>
#include <libknot/error.h>
#include <libknot/mm_ctx.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt_cookie.h> // branch dns-cookies-wip
#include <stdlib.h>
#include <string.h>

#include "daemon/engine.h"
#include "lib/cookies/cache.h"
#include "lib/cookies/control.h"
#include "lib/module.h"
#include "lib/layer.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies",  fmt)

/**
 * Check whether supplied client cookie was generated from given client secret
 * and address.
 *
 * TODO -- The context must store sent cookies and server addresses in order
 * to make the process more reliable.
 */
static int check_client_cookie(const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                               const void *clnt_sockaddr,
                               const void *srvr_sockaddr,
                               const struct secret_quantity *secret)
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
 * Obtain address from query/response context if if can be obtained.
 */
static const struct sockaddr *passed_server_sockaddr(const struct kr_query *qry)
{
	assert(qry);

	const struct sockaddr *tmp_sockaddr = NULL;
	if (qry->rsource.ip4.sin_family == AF_INET ||
	    qry->rsource.ip4.sin_family == AF_INET6) {
		tmp_sockaddr = (struct sockaddr *) &qry->rsource.ip4;
		WITH_DEBUG {
			char addr_str[INET6_ADDRSTRLEN];
			(void *) &qry->rsource.ip4.sin_addr;
			(void *) &qry->rsource.ip6.sin6_addr;
			inet_ntop(tmp_sockaddr->sa_family,
			          (tmp_sockaddr->sa_family == AF_INET) ?
			              (void *) &qry->rsource.ip4.sin_addr :
			              (void *) &qry->rsource.ip6.sin6_addr,
			          addr_str, sizeof(addr_str));
			DEBUG_MSG(NULL,
			          "obtained response address '%s' from query context \n",
			          addr_str);
		}
	}

	return tmp_sockaddr;
}

/**
 * Tries to guess the name server address from the reputation mechanism.
 */
static const struct sockaddr *guess_server_addr(const struct kr_nsrep *nsrep,
                                                const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                                                const struct secret_quantity *secret)
{
	assert(nsrep && cc && secret);

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

/**
 * Obtain pointer to server socket address that matches obtained cookie.
 * @param sockaddr pointer to socket address to be set
 * @param is_current set to true if the cookie was generate from current secret
 * @param cc client cookie from the response
 * @param cntr cookie control structure
 * @return kr_ok() if matching address found, error code else
 */
static int srvr_sockaddr_cc_check(const struct sockaddr **sockaddr, bool *is_current,
                                  const struct kr_query *qry,
                                  const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                                  const struct cookies_control *cntrl)
{
	assert(sockaddr && is_current && qry && cc && cntrl);

	const struct sockaddr *tmp_sockaddr = passed_server_sockaddr(qry);

	/* The address must correspond with the client cookie. */
	if (tmp_sockaddr) {
		int ret = check_client_cookie(cc, NULL, tmp_sockaddr,
		                              cntrl->current_cs);
		bool have_current = (ret == kr_ok());
		if ((ret != kr_ok()) && cntrl->recent_cs) {
			ret = check_client_cookie(cc, NULL, tmp_sockaddr,
		                              cntrl->recent_cs);
		}
		if (ret == kr_ok()) {
			*sockaddr = tmp_sockaddr;
			*is_current = have_current;
		}
		return ret;
	}

	if (!cc || !cntrl) {
		return kr_error(EINVAL);
	}

	DEBUG_MSG(NULL, "%s\n",
	          "guessing response address from ns reputation");

	/* Abusing name server reputation mechanism to guess IP addresses. */
	const struct kr_nsrep *ns = &qry->ns;
	tmp_sockaddr = guess_server_addr(ns, cc, cntrl->current_cs);
	bool have_current = (tmp_sockaddr != NULL);
	if (!tmp_sockaddr && cntrl->recent_cs) {
		/* Try recent client secret to check obtained cookie. */
		tmp_sockaddr = guess_server_addr(ns, cc, cntrl->recent_cs);
	}
	if (tmp_sockaddr) {
		*sockaddr = tmp_sockaddr;
		*is_current = have_current;
	}

	return tmp_sockaddr ? kr_ok() : kr_error(EINVAL);
}

#define MAX_COOKIE_OPT_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)

/**
 * Obtain cookie from cache.
 * @note The ttl and current time are respected. Outdated entries are ignored.
 */
static bool materialise_cookie_opt(struct kr_cache *cache,
                                   const struct sockaddr *sockaddr,
                                   uint32_t timestamp, bool remove_outdated,
                                   uint8_t cookie_opt[MAX_COOKIE_OPT_LEN])
{
	assert(cache && sockaddr);

	bool found = false;
	struct timed_cookie timed_cookie = { 0, };

	struct kr_cache_txn txn;
	kr_cache_txn_begin(cache, &txn, KNOT_DB_RDONLY);
	int ret = kr_cookie_cache_peek_cookie(&txn, sockaddr, &timed_cookie,
	                                      &timestamp);
	if (ret != kr_ok()) {
		kr_cache_txn_abort(&txn);
		return false;
	}
	assert(timed_cookie.cookie_opt);

	if (remove_outdated && (timed_cookie.ttl < timestamp)) {
		/* Outdated entries must be removed. */
		kr_cache_txn_abort(&txn);
		kr_cache_txn_begin(cache, &txn, 0);
		DEBUG_MSG(NULL, "%s\n", "removing outdated entry from cache");
		kr_cookie_cache_remove_cookie(&txn, sockaddr);
		kr_cache_txn_commit(&txn);
		return false;
	}

	size_t cookie_opt_size = knot_edns_opt_get_length(timed_cookie.cookie_opt) + KNOT_EDNS_OPTION_HDRLEN;
	assert(cookie_opt_size <= MAX_COOKIE_OPT_LEN);

	if (cookie_opt) {
		memcpy(cookie_opt, timed_cookie.cookie_opt, cookie_opt_size);
	}
	kr_cache_txn_abort(&txn);
	return true;
}

static bool is_cookie_cached(struct kr_cache *cache,
                             const struct sockaddr *sockaddr,
                             uint32_t timestamp,
                             const uint8_t *pkt_cookie_opt)
{
	assert(cache && sockaddr && pkt_cookie_opt);

	uint8_t cached_cookie_opt[MAX_COOKIE_OPT_LEN];

	bool have_cached = materialise_cookie_opt(cache, sockaddr, timestamp,
	                                          false, cached_cookie_opt);
	if (!have_cached) {
		return false;
	}

	uint16_t pkt_cookie_opt_size = knot_edns_opt_get_length(pkt_cookie_opt) + KNOT_EDNS_OPTION_HDRLEN;
	uint16_t cached_cookie_size = knot_edns_opt_get_length(cached_cookie_opt) + KNOT_EDNS_OPTION_HDRLEN;

	if (pkt_cookie_opt_size != cached_cookie_size) {
		return false;
	}

	return memcmp(pkt_cookie_opt, cached_cookie_opt, pkt_cookie_opt_size) == 0;
}

/** Process response. */
static int check_response(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	if (!kr_cookies_control.enabled) {
		return ctx->state;
	}

	/* Obtain cookie if present in response. Don't check content. */
	uint8_t *pkt_cookie_opt = NULL;
	if (knot_pkt_has_edns(pkt)) {
		pkt_cookie_opt = knot_edns_get_option(pkt->opt_rr,
		                                      KNOT_EDNS_OPTION_COOKIE);
	}

	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;

	struct kr_cache *cache = &kr_cookies_control.cache;

	const struct sockaddr *srvr_sockaddr = passed_server_sockaddr(qry);

	if (!pkt_cookie_opt && srvr_sockaddr &&
	    materialise_cookie_opt(cache, srvr_sockaddr, qry->timestamp.tv_sec,
	                           true, NULL)) {
		/* We haven't received any cookies although we should. */
		DEBUG_MSG(NULL, "%s\n", "expected to receive a cookie but none received");
		return KNOT_STATE_FAIL;
	}

	if (!pkt_cookie_opt) {
		/* Don't do anything if no cookies received. */
		return ctx->state;
	}

	uint8_t *pkt_cookie_data = knot_edns_opt_get_data(pkt_cookie_opt);
	uint16_t pkt_cookie_len = knot_edns_opt_get_length(pkt_cookie_opt);
	assert(pkt_cookie_data && pkt_cookie_len);

	const uint8_t *pkt_cc = NULL, *pkt_sc = NULL;
	uint16_t pkt_cc_len = 0, pkt_sc_len = 0;

	/* Check cookie semantics. */
	int ret = knot_edns_opt_cookie_parse(pkt_cookie_data, pkt_cookie_len,
	                                     &pkt_cc, &pkt_cc_len,
	                                     &pkt_sc, &pkt_sc_len);
	if (ret != KNOT_EOK || !pkt_sc) {
		DEBUG_MSG(NULL, "%s\n", "received malformed DNS cookie or server cookie missing");
		return KNOT_STATE_FAIL;
	}
	assert(pkt_cc_len == KNOT_OPT_COOKIE_CLNT);

	DEBUG_MSG(NULL, "%s\n", "checking response for received cookies");

	/* Check server address against received client cookie. */
	srvr_sockaddr = NULL;
	bool returned_current = false;
	ret = srvr_sockaddr_cc_check(&srvr_sockaddr, &returned_current, qry,
	                             pkt_cc, &kr_cookies_control);
	if (ret != kr_ok()) {
		DEBUG_MSG(NULL, "%s\n", "could not match received cookie");
		return KNOT_STATE_FAIL;
	}
	assert(srvr_sockaddr);

	/* Don't cache received cookies that don't match the current secret. */
	if (returned_current &&
	    !is_cookie_cached(cache, srvr_sockaddr, qry->timestamp.tv_sec,
	                      pkt_cookie_opt)) {
		DEBUG_MSG(NULL, "%s\n", "caching server cookie");

		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(cache, &txn, 0) != 0) {
			/* Could not acquire cache. */
			return ctx->state;
		}

		struct timed_cookie timed_cookie = { COOKIE_TTL, pkt_cookie_opt };

		ret = kr_cookie_cache_insert_cookie(&txn, srvr_sockaddr,
		                                    &timed_cookie,
		                                    qry->timestamp.tv_sec);
		if (ret != kr_ok()) {
			kr_cache_txn_abort(&txn);
		} else {
			DEBUG_MSG(NULL, "%s\n", "cookie_cached");
			kr_cache_txn_commit(&txn);
		}
	}

	uint16_t rcode = knot_pkt_get_ext_rcode(pkt);
	if (rcode == KNOT_RCODE_BADCOOKIE) {
		struct kr_query *next = NULL;
		if (!(qry->flags & QUERY_BADCOOKIE_AGAIN)) {
			/* Received first BADCOOKIE, regenerate query. */
			next = kr_rplan_push(&req->rplan, qry->parent,
			                     qry->sname,  qry->sclass,
			                     qry->stype);
		}

		if (next) {
			DEBUG_MSG(NULL, "%s\n", "BADCOOKIE querying again");
			qry->flags |= QUERY_BADCOOKIE_AGAIN;
		} else {
			/* Either the planning of second request failed or
			 * BADCOOKIE received for the second time.
			 * Fall back to TCP. */
			DEBUG_MSG(NULL, "%s\n", "falling back to TCP");
			qry->flags &= ~QUERY_BADCOOKIE_AGAIN;
			qry->flags |= QUERY_TCP;
		}

		return KNOT_STATE_CONSUME;
	}

	return ctx->state;
}

/** Module implementation. */

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

KR_MODULE_EXPORT(cookies)
