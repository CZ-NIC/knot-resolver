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

#pragma once

#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt_cookie.h>
#include <stdbool.h>

#include "lib/cache.h"
#include "lib/defines.h"

/** Maximal size of a cookie option. */
#define KR_COOKIE_OPT_MAX_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)

/** Holds secret quantity. */
struct kr_cookie_secret {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/** Default client secret. */
KR_EXPORT
extern struct kr_cookie_secret dflt_cs;

/** DNS cookies controlling structure. */
struct kr_cookie_ctx {
	bool enabled; /*!< Enabled/disables DNS cookies functionality. */

	struct kr_cookie_secret *current_cs; /*!< current client secret */
	struct kr_cookie_secret *recent_cs; /*!< recent client secret */

//	struct kr_cache cache; /*!< Server cookies cache. */
};

/** Global cookie control context. */
KR_EXPORT
extern struct kr_cookie_ctx kr_glob_cookie_ctx;

/**
 * Get pointers to IP address bytes.
 * @param sockaddr socket address
 * @param addr pointer to address
 * @param len address length
 */
int kr_address_bytes(const void *sockaddr, const uint8_t **addr, size_t *len);

/**
 * Compute client cookie.
 * @not At least one of the arguments must be non-null.
 * @param cc_buf        Buffer to which to write the cookie into.
 * @param clnt_sockaddr Client address.
 * @param srvr_sockaddr Server address.
 * @param secret        Client secret quantity.
 */
KR_EXPORT
int kr_client_cokie_fnv64(uint8_t cc_buf[KNOT_OPT_COOKIE_CLNT],
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          const struct kr_cookie_secret *secret);

/**
 * Insert a DNS cookie into query packet.
 * @note The packet must already contain ENDS section.
 * @param cntrl         Cookie control structure.
 * @param cookie_cache  Cookie cache.
 * @param clnt_sockaddr Client address.
 * @param srvr_sockaddr Server address.
 * @param pkt           DNS request packet.
 */
KR_EXPORT
int kr_request_put_cookie(const struct kr_cookie_ctx *cntrl,
                          struct kr_cache *cookie_cache,
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          knot_pkt_t *pkt);
