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

#include <libknot/cookies/server.h>

#include "lib/defines.h"

/** Holds description of server cookie hashing algorithms. */
struct kr_srvr_cookie_alg_descr {
	const char *name; /**< Algorithm name. */
	struct knot_sc_alg alg; /**< Algorithm. */
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
int kr_srvr_cookie_check(const struct knot_dns_cookies *cookies,
                         const struct knot_scookie_check_ctx *check_ctx,
                         const struct kr_srvr_cookie_alg_descr *sc_alg);
