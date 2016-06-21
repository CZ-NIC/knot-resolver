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

#include <libknot/cookies/client.h>

#include "lib/defines.h"

/** Maximal size of a cookie option. */
#define KR_COOKIE_OPT_MAX_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)

/** Holds description of client cookie hashing algorithms. */
struct kr_clnt_cookie_alg_descr {
	const char *name; /**< Hash algorithgm name. */
	struct knot_cc_alg alg; /**< Hash algorithm. */
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
                         const struct knot_ccookie_input *input,
                         const struct kr_clnt_cookie_alg_descr *cc_alg);
