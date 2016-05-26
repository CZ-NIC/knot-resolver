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

#define KR_COOKIE_PLD_MAX 44 /* TODO -- Define in libknot. */

/** Holds secret quantity. */
struct secret_quantity {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/* Default client secret. */
KR_EXPORT
extern struct secret_quantity dflt_cs;

/** DNSSEC cookies controlling structure. */
struct cookies_control {
	bool enabled; /*!< Enabled/disables DNS cookies functionality. */

	struct secret_quantity *current_cs; /*!< current client secret */
	struct secret_quantity *recent_cs; /*!< recent client secret */

	struct kr_cache cache; /*!< Server cookies cache. */
};

/** Global cookies control. */
KR_EXPORT
extern struct cookies_control kr_cookies_control;

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
                          const struct secret_quantity *secret);

/**
 * Insert a DNS cookie into query packet.
 * @note The packet must already contain ENDS section.
 * @param cntrl         Cookie control structure.
 * @param clnt_sockaddr Client address.
 * @param srvr_sockaddr Server address.
 * @param pkt           DNS request packet.
 */
KR_EXPORT
int kr_request_put_cookie(const struct cookies_control *cntrl,
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          knot_pkt_t *pkt);
