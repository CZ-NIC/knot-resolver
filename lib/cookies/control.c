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

//#define MODULE_DEBUG_MSGS 1 /* Comment out if debug messages are not desired. */

#include <arpa/inet.h> /* inet_ntop() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <libknot/error.h>

#include "contrib/fnv/fnv.h"
#include "lib/cookies/cache.h"
#include "lib/cookies/control.h"
#include "lib/layer.h"
#include "lib/utils.h"

#if defined(MODULE_DEBUG_MSGS)
#  define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies_control",  fmt)
#else /* !defined(MODULE_DEBUG_MSGS) */
#  define DEBUG_MSG(qry, fmt...) do { } while (0)
#endif /* defined(MODULE_DEBUG_MSGS) */

/* Default client secret. */
struct kr_cookie_secret dflt_cs = {
	.size = KNOT_OPT_COOKIE_CLNT,
	.data = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

struct kr_cookie_ctx kr_glob_cookie_ctx = {
	.enabled = false,
	.current_cs = &dflt_cs
};

static int opt_rr_add_cookies(knot_rrset_t *opt_rr,
                              uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                              uint8_t *sc, uint16_t sc_len,
                              knot_mm_t *mm)
{
	uint16_t cookies_size = 0;
	uint8_t *cookies_data = NULL;

	cookies_size = knot_edns_opt_cookie_data_len(sc_len);

	int ret = knot_edns_reserve_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   cookies_size, &cookies_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(cookies_data != NULL);

	ret = knot_edns_opt_cookie_create(cc, sc, sc_len,
	                                  cookies_data, &cookies_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(cookies_size == knot_edns_opt_cookie_data_len(sc_len));

	return KNOT_EOK;
}

static int opt_rr_add_option(knot_rrset_t *opt_rr, uint8_t *option,
                             knot_mm_t *mm)
{
	assert(opt_rr && option);

	uint8_t *reserved_data = NULL;
	uint16_t opt_code = knot_edns_opt_get_code(option);
	uint16_t opt_len = knot_edns_opt_get_length(option);
	uint8_t *opt_data = knot_edns_opt_get_data(option);

	int ret = knot_edns_reserve_option(opt_rr, opt_code,
	                                   opt_len, &reserved_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(reserved_data);

	memcpy(reserved_data, opt_data, opt_len);
	return KNOT_EOK;
}

int kr_address_bytes(const void *sockaddr, const uint8_t **addr, size_t *len)
{
	if (!sockaddr || !addr || !len) {
		return kr_error(EINVAL);
	}

	assert(sockaddr && addr && len);

	int addr_family = ((struct sockaddr *) sockaddr)->sa_family;

	switch (addr_family) {
	case AF_INET:
		*addr = (uint8_t *) &((struct sockaddr_in *) sockaddr)->sin_addr;
		*len = 4;
		break;
	case AF_INET6:
		*addr = (uint8_t *) &((struct sockaddr_in6 *) sockaddr)->sin6_addr;
		*len = 16;
		break;
	default:
		*addr = NULL;
		*len = 0;
		addr_family = AF_UNSPEC;
		DEBUG_MSG(NULL, "%s\n", "could obtain IP address");
		return kr_error(EINVAL);
		break;
	}

	WITH_DEBUG {
		char ns_str[INET6_ADDRSTRLEN];
		inet_ntop(addr_family, *addr, ns_str, sizeof(ns_str));
		DEBUG_MSG(NULL, "obtaned IP address '%s'\n", ns_str);
	}

	return kr_ok();
}

int kr_client_cokie_fnv64(uint8_t cc_buf[KNOT_OPT_COOKIE_CLNT],
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          const struct kr_cookie_secret *secret)
{
	if (!cc_buf) {
		return kr_error(EINVAL);
	}

	if (!clnt_sockaddr && !srvr_sockaddr &&
	    !(secret && secret->size && secret->data)) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t size = 0;

	Fnv64_t hash_val = FNV1A_64_INIT;

	/* Client address currently always ignored. */
#if 0
	if (clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(clnt_sockaddr, &addr, &size)) {
			assert(addr && size);
			hash_val = fnv_64a_buf(addr, size, hash_val);
		}
	}
#endif

	if (srvr_sockaddr) {
		if (kr_ok() == kr_address_bytes(srvr_sockaddr, &addr, &size)) {
			assert(addr && size);
			hash_val = fnv_64a_buf((void *) addr, size, hash_val);
		}
	}

	if (secret && secret->size && secret->data) {
		DEBUG_MSG(NULL, "%s\n", "adding client secret into cookie");
		hash_val = fnv_64a_buf((void *) addr, size, hash_val);
	}

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));

	memcpy(cc_buf, &hash_val, KNOT_OPT_COOKIE_CLNT);

	return kr_ok();
}

/**
 * Check whether there is a cached cookie that matches the current client
 * cookie.
 */
static const uint8_t *peek_and_check_cc(struct kr_cache_txn *txn,
                                        const void *sockaddr,
                                        const uint8_t cc[KNOT_OPT_COOKIE_CLNT])
{
	assert(txn && sockaddr && cc);

	uint32_t timestamp = 0;
	struct timed_cookie timed_cookie = { 0, };

	int ret = kr_cookie_cache_peek_cookie(txn, sockaddr, &timed_cookie,
	                                      &timestamp);
	if (ret != kr_ok()) {
		return NULL;
	}
	assert(timed_cookie.cookie_opt);

	/* Ignore the timestamp and time to leave. If the cookie is in cache
	 * then just use it. The cookie control should be prerformed in the
	 * cookie module/layer. */

	const uint8_t *cached_cc = knot_edns_opt_get_data((uint8_t *) timed_cookie.cookie_opt);

	if (0 == memcmp(cc, cached_cc, KNOT_OPT_COOKIE_CLNT)) {
		return timed_cookie.cookie_opt;
	}

	return NULL;
}

int kr_request_put_cookie(const struct kr_cookie_ctx *cntrl,
                          struct kr_cache *cookie_cache,
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          knot_pkt_t *pkt)
{
	assert(cntrl);
	assert(pkt);

	if (!pkt->opt_rr) {
		return kr_ok();
	}

	if (!cntrl->current_cs || !cookie_cache) {
		return kr_error(EINVAL);
	}

	/* Generate client cookie.
	 * TODO -- generate client cookie from client address, server address
	 * and secret quantity. */
	uint8_t cc[KNOT_OPT_COOKIE_CLNT];
	int ret = kr_client_cokie_fnv64(cc, clnt_sockaddr, srvr_sockaddr,
	                                cntrl->current_cs);
	if (ret != kr_ok()) {
		return ret;
	}

	struct kr_cache_txn txn;
	ret = kr_cache_txn_begin(cookie_cache, &txn, KNOT_DB_RDONLY);
	if (ret != kr_ok()) {
		return kr_error(EIO);
	}
	const uint8_t *cached_cookie = peek_and_check_cc(&txn, srvr_sockaddr,
	                                                 cc);

	/* This is a very nasty hack that prevents the packet to be corrupted
	 * when using contemporary 'Cookie interface'. */
	assert(pkt->current == KNOT_ADDITIONAL);
	pkt->sections[KNOT_ADDITIONAL].count -= 1;
	pkt->rrset_count -= 1;
	pkt->size -= knot_edns_wire_size(pkt->opt_rr);
	knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);
#if 0
	/* Reclaim reserved size -- does not work as intended.. */
	ret = knot_pkt_reclaim(pkt, knot_edns_wire_size(pkt->opt_rr));
	if (ret != KNOT_EOK) {
		return ret;
	}
#endif

	if (cached_cookie) {
		ret = opt_rr_add_option(pkt->opt_rr, (uint8_t *) cached_cookie,
		                        &pkt->mm);
	} else {
		ret = opt_rr_add_cookies(pkt->opt_rr, cc, NULL, 0, &pkt->mm);
	}

	kr_cache_txn_abort(&txn);

	/* Write to packet. */
	assert(pkt->current == KNOT_ADDITIONAL);
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}
