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
	size_t secret_len;
};

/** Client cookie algorithm type. */
typedef int (clnt_cookie_alg_t)(const struct kr_clnt_cookie_input *input,
                                uint8_t *);

/** Holds description of client cookie hashing algorithms. */
struct kr_clnt_cookie_alg_descr {
	clnt_cookie_alg_t *func; /**< Pointer to has function. */
	const char *name; /**< Hash function name. */
};

/**
 * List of available client cookie algorithms.
 *
 * Last element contains all null entries.
 */
KR_EXPORT
extern const struct kr_clnt_cookie_alg_descr kr_clnt_cookie_algs[];

/**
 * @brief Return pointer to client cookie hash function with given name.
 * @param cc_algs List of available algorithms.
 * @param name    Algorithm name.
 * @return pointer to function or NULL if not found.
 */
KR_EXPORT
clnt_cookie_alg_t *kr_clnt_cookie_alg_func(const struct kr_clnt_cookie_alg_descr cc_algs[],
                                           const char *name);

/**
 * @brief Return name of given client cookie hash function.
 * @param cc_algs List of available algorithms.
 * @param func    Sought algorithm function.
 * @return pointer to string or NULL if not found.
 */
KR_EXPORT
const char *kr_clnt_cookie_alg_name(const struct kr_clnt_cookie_alg_descr cc_algs[],
                                    clnt_cookie_alg_t *func);

/**
 * Get pointers to IP address bytes.
 * @param sockaddr socket address
 * @param addr pointer to address
 * @param len address length
 * @return kr_ok() on success, error code else.
 */
int kr_address_bytes(const void *sockaddr, const uint8_t **addr, size_t *len);

/**
 * Compute client cookie using FNV-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @return kr_ok() on success, error code else.
 */
KR_EXPORT
int kr_clnt_cookie_alg_fnv64(const struct kr_clnt_cookie_input *input,
                             uint8_t cc_out[KNOT_OPT_COOKIE_CLNT]);

/**
 * Compute client cookie using HMAC_SHA256-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @return kr_ok() on success, error code else.
 */
KR_EXPORT
int kr_clnt_cookie_alg_hmac_sha256_64(const struct kr_clnt_cookie_input *input,
                                      uint8_t cc_buf[KNOT_OPT_COOKIE_CLNT]);
