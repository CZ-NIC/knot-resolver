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

/** Inbound server cookie checking context. */
struct kr_srvr_cookie_check_ctx {
	const void *clnt_sockaddr; /**< Client (remote) socket address. */
	const uint8_t *secret_data; /**< Server secret data. */
	size_t secret_len; /**< Server secret data length. */
};

/** Inbound server cookie content structure. */
struct kr_srvr_cookie_inbound {
	const uint8_t *clnt_cookie; /**< Client cookie, `KNOT_OPT_COOKIE_CLNT` bytes long. */
	uint32_t nonce; /**< Some value. */
	uint32_t time; /**< Time stamp. */
	const uint8_t *hash_data; /**< Hash data. */
	uint16_t hash_len; /**< Hash data length. */
};

/** Server cookie creation context. */
struct kr_srvr_cookie_input {
	const uint8_t *clnt_cookie; /**< Client cookie, must be `KNOT_OPT_COOKIE_CLNT` bytes long. */
	uint32_t nonce; /**< Some generated value. */
	uint32_t time; /**< Cookie time stamp. */
	struct kr_srvr_cookie_check_ctx srvr_data; /**< Data known to the server. */
};

/**
 * @brief Server cookie parser function type.
 * @param cookie_data Entire cookie option data (without option header).
 * @param data_len    Cookie data length.
 * @param inbound     Inbound cookie structure to be set.
 * @return kr_ok() or error code.
 */
typedef int (srvr_cookie_parse_t)(const uint8_t *cookie_data, uint16_t data_len,
                                  struct kr_srvr_cookie_inbound *inbound);
/**
 * @brief Server cookie generator function type.
 * @param input   Data which to generate the cookie from.
 * @param sc_out  Buffer to write the resulting client cookie data into.
 * @param sc_size On input must contain size of the buffer, on successful return contains size of actual written data.
 * @return kr_ok() or error code
 */
typedef int (srvr_cookie_gen_t)(const struct kr_srvr_cookie_input *input,
                                uint8_t *sc_out, size_t *sc_size);

/** Holds description of server cookie hashing algorithms. */
struct kr_srvr_cookie_alg_descr {
	const char *name; /** Server cookie algorithm name. */
	const uint16_t srvr_cookie_size; /**< Size of the generated server cookie. */
	const srvr_cookie_parse_t *opt_parse_func; /**< Cookie option parser function. */
	const srvr_cookie_gen_t *gen_func; /*< Cookie generator function. */
};

/**
 * List of available server cookie algorithms.
 *
 * Last element contains all null entries.
 */
KR_EXPORT
extern const struct kr_srvr_cookie_alg_descr kr_srvr_cookie_algs[];

/**
 * @brief Check whether supplied client and server cookie match.
 * @param cookie_opt Entire cookie option, must contain server cookie.
 * @param check_ctx  Data known to the server needed for cookie validation.
 * @param sc_alg     Server cookie algorithm.
 * @return kr_ok() if check OK, error code else.
 */
KR_EXPORT
int kr_srvr_cookie_check(const uint8_t *cookie_opt,
                         const struct kr_srvr_cookie_check_ctx *check_ctx,
                         const struct kr_srvr_cookie_alg_descr *sc_alg);
