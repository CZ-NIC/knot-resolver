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

#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdint.h>
#include <libknot/error.h>
#include <libknot/rrtype/opt_cookie.h>

#include "lib/cookies/control.h"
#include "lib/layer.h"
#include "lib/utils.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies_control",  fmt)

static uint8_t cc[KNOT_OPT_COOKIE_CLNT] = { 1, 2, 3, 4, 5, 6, 7, 8};

static struct secret_quantity client = {
	.size = KNOT_OPT_COOKIE_CLNT,
	.secret = cc
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

int prepare_client_cookie(uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                          const void *clnt_addr,
                          const void *srvr_addr,
                          const struct secret_quantity *csq)
{
	assert(cc);
	assert(srvr_addr);
	assert(csq);

	assert(csq->size >= KNOT_OPT_COOKIE_CLNT);

	/* According to the draft (section A.1) the recommended sequence is
	 * client IP address | server IP address , client secret. */

	if (clnt_addr) {
		int addr_family = ((struct sockaddr *) clnt_addr)->sa_family;
		if (addr_family == AF_INET) {
			clnt_addr = &((struct sockaddr_in *) clnt_addr)->sin_addr;
		} else if (addr_family == AF_INET6) {
			clnt_addr = &((struct sockaddr_in6 *) clnt_addr)->sin6_addr;
		} else {
			//assert(0);
			//return kr_error(EINVAL);
			addr_family = AF_UNSPEC;
			DEBUG_MSG(NULL, "%s\n", "could not obtain client IP address for client cookie");
		}

		if (addr_family != AF_UNSPEC) {
			WITH_DEBUG {
				char ns_str[INET6_ADDRSTRLEN];
				inet_ntop(addr_family, clnt_addr, ns_str, sizeof(ns_str));
				DEBUG_MSG(NULL, "adding client IP address '%s' into client cookie\n", ns_str);
			}
		}
	}

	if (srvr_addr) {
		int addr_family = ((struct sockaddr *) srvr_addr)->sa_family;
		if (addr_family == AF_INET) {
			srvr_addr = &((struct sockaddr_in *) srvr_addr)->sin_addr;
		} else if (addr_family == AF_INET6) {
			srvr_addr = &((struct sockaddr_in6 *) srvr_addr)->sin6_addr;
		} else {
			addr_family = AF_UNSPEC;
			DEBUG_MSG(NULL, "%s\n", "could not obtain server IP address for client cookie");
		}

		if (addr_family != AF_UNSPEC) {
			WITH_DEBUG {
				char ns_str[INET6_ADDRSTRLEN];
				inet_ntop(addr_family, srvr_addr, ns_str, sizeof(ns_str));
				DEBUG_MSG(NULL, "adding server address '%s' into client cookie\n", ns_str);
			}
		}
	}

	memcpy(cc, csq->secret, KNOT_OPT_COOKIE_CLNT);
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

	int ret = prepare_client_cookie(cc, clnt_sockaddr, srvr_sockaddr,
	                                cntrl->client);

	/* Reclaim reserved size. */
	ret = knot_pkt_reclaim(pkt, knot_edns_wire_size(pkt->opt_rr));
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* TODO -- generate client cookie from client address, server address
	 * and secret quantity. */
	ret = opt_rr_add_cookies(pkt->opt_rr, cc, NULL, 0, &pkt->mm);

	/* Write to packet. */
	assert(pkt->current == KNOT_ADDITIONAL);
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}
