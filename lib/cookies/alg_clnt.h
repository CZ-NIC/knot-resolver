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

/** Maximal size of a cookie option. */
#define KR_COOKIE_OPT_MAX_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)

/** Client cookie computation context. */
struct kr_clnt_cookie_input {
	const void *clnt_sockaddr; /**< Client (local) socket address. */
	const void *srvr_sockaddr; /**< Server (remote) socket address. */
	const uint8_t *secret_data; /**< Client secret data. */
	size_t secret_len; /**< Secret data length. */
};

/**
 * @brief Client cookie generator function type.
 * @param input Data which to generate the cookie from.
 * @param cc_out Buffer to write the resulting client cookie data into.
 * @param cc_len Set to length of buffer. After successful return contains size of client cookie.
 * @return kr_ok() or error code
 */
typedef int (clnt_cookie_alg_t)(const struct kr_clnt_cookie_input *input,
                                uint8_t *cc_out, uint16_t *cc_len);

/** Holds description of client cookie hashing algorithms. */
struct kr_clnt_cookie_alg_descr {
	const char *name; /**< Hash function name. */
	clnt_cookie_alg_t *func; /**< Pointer to hash function. */
};

/**
 * List of available client cookie algorithms.
 *
 * Last element contains all null entries.
 */
KR_EXPORT
extern const struct kr_clnt_cookie_alg_descr kr_clnt_cookie_algs[];

/**
 * @brief Return pointer to client cookie algorithm with given name.
 * @param cc_algs List of available algorithms.
 * @param name    Algorithm name.
 * @return pointer to algorithm or NULL if not found.
 */
KR_EXPORT
const struct kr_clnt_cookie_alg_descr *kr_clnt_cookie_alg(const struct kr_clnt_cookie_alg_descr cc_algs[],
                                                          const char *name);

/**
 * @brief Get pointers to IP address bytes.
 * @param sockaddr socket address
 * @param addr pointer to address
 * @param len address length
 * @return kr_ok() on success, error code else.
 */
int kr_address_bytes(const void *sockaddr, const uint8_t **addr, size_t *len);

/**
 * @brief Check whether supplied client cookie was generated from given client
 * secret and address.
 * @param cc     Client cookie that should be checked.
 * @param cc_len Client cookie size.
 * @param input  Input cookie algorithm parameters.
 * @param cc_alg Client cookie algorithm.
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_clnt_cookie_check(const uint8_t *cc, uint16_t cc_len,
                         const struct kr_clnt_cookie_input *input,
                         const struct kr_clnt_cookie_alg_descr *cc_alg);
