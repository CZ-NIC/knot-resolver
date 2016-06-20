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

#include <libknot/rrtype/opt_cookie.h>

#include "lib/defines.h"

/** Convenience Structure holding both, server and client, cookies. */
struct kr_dns_cookies {
	const uint8_t *cc; /**< Client cookie. */
	uint16_t cc_len; /**< Client cookie size. */
	const uint8_t *sc; /**< Server cookie. */
	uint16_t sc_len; /**< Server cookie size. */
};

/** Inbound server cookie checking context. */
struct kr_srvr_cookie_check_ctx {
	const void *clnt_sockaddr; /**< Client (remote) socket address. */
	const uint8_t *secret_data; /**< Server secret data. */
	size_t secret_len; /**< Server secret data length. */
};

/** Inbound server cookie content structure. */
struct kr_srvr_cookie_inbound {
	uint32_t nonce; /**< Some value. */
	uint32_t time; /**< Time stamp. */
	const uint8_t *hash_data; /**< Hash data. */
	uint16_t hash_len; /**< Hash data length. */
};

/** Server cookie creation context. */
struct kr_srvr_cookie_input {
	const uint8_t *clnt_cookie; /**< Client cookie. */
	uint16_t clnt_cookie_len; /**< Client cookie size. */
	uint32_t nonce; /**< Some generated value. */
	uint32_t time; /**< Cookie time stamp. */
	const struct kr_srvr_cookie_check_ctx *srvr_data; /**< Data known to the server. */
};

/**
 * @brief Server cookie parser function type.
 * @param sc        Server cookie data.
 * @param data_len  Server cookie data length.
 * @param inbound   Inbound cookie structure to be set.
 * @return kr_ok() or error code.
 */
typedef int (srvr_cookie_parse_t)(const uint8_t *sc, uint16_t sc_len,
                                  struct kr_srvr_cookie_inbound *inbound);
/**
 * @brief Server cookie generator function type.
 * @param input  Data which to generate the cookie from.
 * @param sc_out Buffer to write the resulting client cookie data into.
 * @param sc_len On input must contain size of the buffer, on successful return contains size of actual written data.
 * @return kr_ok() or error code
 */
typedef int (srvr_cookie_gen_t)(const struct kr_srvr_cookie_input *input,
                                uint8_t *sc_out, uint16_t *sc_len);

/** Holds description of server cookie hashing algorithms. */
struct kr_srvr_cookie_alg_descr {
	const char *name; /**< Server cookie algorithm name. */
	const uint16_t srvr_cookie_size; /**< Size of the generated server cookie. */
	srvr_cookie_parse_t *opt_parse_func; /**< Cookie option parser function. */
	srvr_cookie_gen_t *gen_func; /**< Cookie generator function. */
};

/**
 * List of available server cookie algorithms.
 *
 * Last element contains all null entries.
 */
KR_EXPORT
extern const struct kr_srvr_cookie_alg_descr kr_srvr_cookie_algs[];

/**
 * @brief Return pointer to server cookie algorithm with given name.
 * @param sc_algs List of available algorithms.
 * @param name    Algorithm name.
 * @return pointer to algorithm or NULL if not found.
 */
KR_EXPORT
const struct kr_srvr_cookie_alg_descr *kr_srvr_cookie_alg(const struct kr_srvr_cookie_alg_descr sc_algs[],
                                                          const char *name);

/**
 * @brief Check whether supplied client and server cookie match.
 * @param cookies   Cookie data.
 * @param check_ctx Data known to the server needed for cookie validation.
 * @param sc_alg    Server cookie algorithm.
 * @return kr_ok() if check OK, error code else.
 */
KR_EXPORT
int kr_srvr_cookie_check(const struct kr_dns_cookies *cookies,
                         const struct kr_srvr_cookie_check_ctx *check_ctx,
                         const struct kr_srvr_cookie_alg_descr *sc_alg);
