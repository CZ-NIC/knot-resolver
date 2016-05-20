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

#include <arpa/inet.h> /* inet_ntop() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdint.h>
#include <libknot/error.h>

#include "contrib/fnv/fnv.h"
#include "lib/cookies/control.h"
#include "lib/layer.h"
#include "lib/utils.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies_control",  fmt)

static uint8_t cc[KNOT_OPT_COOKIE_CLNT] = { 1, 2, 3, 4, 5, 6, 7, 8};

static struct secret_quantity client = {
	.size = KNOT_OPT_COOKIE_CLNT,
	.data = cc
};

struct cookies_control kr_cookies_control = {
	.enabled = true,
	.client = &client
};

static int opt_rr_add_cookies(knot_rrset_t *opt_rr,
                              uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                              uint8_t *sc, uint16_t sc_len,
                              knot_mm_t *mm)
{
	int ret;
	uint16_t cookies_size = 0;
	uint8_t *cookies_data = NULL;

	cookies_size = knot_edns_opt_cookie_data_len(sc_len);

	ret = knot_edns_reserve_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
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

static void obtain_address(void *sockaddr, uint8_t **addr, size_t *len)
{
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
		return;
		break;
	}

	WITH_DEBUG {
		char ns_str[INET6_ADDRSTRLEN];
		inet_ntop(addr_family, *addr, ns_str, sizeof(ns_str));
		DEBUG_MSG(NULL, "obtaned IP address '%s'\n", ns_str);
	}
}

int kr_client_cokie_fnv64(uint8_t cc_buf[KNOT_OPT_COOKIE_CLNT],
                          void *clnt_sockaddr, void *srvr_sockaddr,
                          struct secret_quantity *secret)
{
	if (!cc_buf) {
		return kr_error(EINVAL);
	}

	if (!clnt_sockaddr && !srvr_sockaddr &&
	    !(secret && secret->size && secret->data)) {
		return kr_error(EINVAL);
	}

	uint8_t *addr = NULL;
	size_t size = 0;

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (clnt_sockaddr) {
		obtain_address(clnt_sockaddr, &addr, &size);
		if (addr && size) {
			hash_val = fnv_64a_buf(addr, size, hash_val);
		}
	}

	if (srvr_sockaddr) {
		obtain_address(srvr_sockaddr, &addr, &size);
		if (addr && size) {
			hash_val = fnv_64a_buf(addr, size, hash_val);
		}
	}

	if (secret && secret->size && secret->data) {
		DEBUG_MSG(NULL, "%s\n", "adding client secret into cookie");
		hash_val = fnv_64a_buf(addr, size, hash_val);
	}

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));

	memcpy(cc_buf, &hash_val, KNOT_OPT_COOKIE_CLNT);

	return kr_ok();
}

int kr_request_put_cookie(struct cookies_control *cntrl, void *clnt_sockaddr,
                          void *srvr_sockaddr, knot_pkt_t *pkt)
{
	assert(cntrl);
	assert(pkt);

	uint8_t cc[KNOT_OPT_COOKIE_CLNT];

	if (!pkt->opt_rr) {
		return kr_ok();
	}

	if (!cntrl->client) {
		return kr_error(EINVAL);
	}

	int ret = kr_client_cokie_fnv64(cc, clnt_sockaddr, srvr_sockaddr,
	                                cntrl->client);

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

	/* TODO -- generate client cookie from client address, server address
	 * and secret quantity. */
	ret = opt_rr_add_cookies(pkt->opt_rr, cc, NULL, 0, &pkt->mm);

	/* Write to packet. */
	assert(pkt->current == KNOT_ADDITIONAL);
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}
