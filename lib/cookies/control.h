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
#include "lib/cookies/alg_srvr.h"
#include "lib/cache.h"
#include "lib/defines.h"

/** Holds secret quantity. */
struct kr_cookie_secret {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/** Default cookie TTL. */
#define DFLT_COOKIE_TTL 72000

/** Holds settings that have direct influence on client cookie values. */
struct kr_clnt_cookie_settings {
	struct kr_cookie_secret *csec; /*!< Client secret data. */
	const struct kr_clnt_cookie_alg_descr *calg; /**< Client cookie algorithm. */
};

/** Holds settings that control client behaviour. */
struct kr_clnt_cookie_ctx {
	bool enabled; /**< Enable/disables client DNS cookies functionality. */

	struct kr_clnt_cookie_settings current; /**< Current cookie client settings. */
	struct kr_clnt_cookie_settings recent; /**< Current cookie client settings. */

	uint32_t cache_ttl; /**< TTL used when caching cookies */
};

/** Holds settings that have direct influence on server cookie values. */
struct kr_srvr_cookie_settings {
	struct kr_cookie_secret *ssec; /*!< Server secret data. */
	const struct kr_srvr_cookie_alg_descr *salg; /**< Server cookie algorithm. */
};

/** Holds settings that control server behaviour. */
struct kr_srvr_cookie_ctx {
	bool enabled; /**< Enable/disables server DNS cookies functionality. */

	struct kr_srvr_cookie_settings current; /**< Current cookie server settings. */
	struct kr_srvr_cookie_settings recent; /**< Current cookie server settings. */
};

/** DNS cookies controlling structure. */
struct kr_cookie_ctx {
	struct kr_clnt_cookie_ctx clnt; /**< Client settings. */
	struct kr_srvr_cookie_ctx srvr; /**< Server settings. */
};

/** Global cookie control context. */
KR_EXPORT
extern struct kr_cookie_ctx kr_glob_cookie_ctx;

/**
 * @brief Insert a DNS cookie into query packet.
 * @note The packet must already contain ENDS section.
 * @param clnt_cntrl    Client cookie control structure.
 * @param cookie_cache  Cookie cache.
 * @param clnt_sockaddr Client address.
 * @param srvr_sockaddr Server address.
 * @param pkt           DNS request packet.
 */
KR_EXPORT
int kr_request_put_cookie(const struct kr_clnt_cookie_settings *clnt_cntrl,
                          struct kr_cache *cookie_cache,
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          knot_pkt_t *pkt);

/**
 * @brief Add cookies into answer.
 * @note Data are only added into the OPT RR.
 * @param input input data to generate server cookie from
 * @param alg algorithm to use
 * @param pkt packet which to put cookie into
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_answer_opt_rr_add_cookies(const struct kr_srvr_cookie_input *input,
                                 const struct kr_srvr_cookie_alg_descr *alg,
                                 knot_pkt_t *pkt);

/**
 * @brief Set RCODE and extended RCODE.
 * @param pkt DNS packet
 * @param whole_rcode RCODE value
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_pkt_set_ext_rcode(knot_pkt_t *pkt, uint16_t whole_rcode);

/**
 * @brief Check whether packet is a server cookie request.
 * @param pkt     Packet to be examined.
 * @param cookies Received cookies.
 * @return Pointer to entire cookie option if is a cookie query, NULL else.
 */
KR_EXPORT
uint8_t *kr_is_cookie_query(const knot_pkt_t *pkt);

/**
 * @brief Parse cookies from cookie option.
 * @param cookie_opt Cookie option.
 * @param cookies    Cookie structure to be set.
 * @return kr_ok() on success, error if cookies are malformed.
 */
KR_EXPORT
int kr_parse_cookie_opt(uint8_t *cookie_opt, struct kr_dns_cookies *cookies);
