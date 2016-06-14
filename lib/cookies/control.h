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

#include "lib/cookies/alg_clnt.h"
#include "lib/cache.h"
#include "lib/defines.h"

/** Holds secret quantity. */
struct kr_cookie_secret {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/** Default client secret. */
KR_EXPORT
extern struct kr_cookie_secret dflt_cs;

/** Default server secret. */
KR_EXPORT
extern struct kr_cookie_secret dflt_ss;

/** Default cookie TTL. */
#define DFLT_COOKIE_TTL 72000

/** DNS cookies controlling structure. */
struct kr_cookie_ctx {
	bool enabled; /**< Enabled/disables DNS cookies functionality. */

	struct kr_cookie_secret *current_cs; /**< current client secret */
	struct kr_cookie_secret *recent_cs; /**< recent client secret */

	uint32_t cache_ttl; /**< TTL used when caching cookies */

	struct kr_cookie_secret *current_ss; /**< current server secret */
	struct kr_cookie_secret *recent_ss; /**< recent server secret */

	const struct kr_clnt_cookie_alg_descr *cc_alg; /**< Client cookie algorithm. */
	const struct kr_srvr_cookie_alg_descr *sc_alg; /**< Server cookie algorithm. */
};

/** Global cookie control context. */
KR_EXPORT
extern struct kr_cookie_ctx kr_glob_cookie_ctx;

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
