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

#include <libknot/rrtype/opt-cookie.h>
#include <netinet/in.h>
#include <stdint.h>

#include "lib/defines.h"
#include "lib/generic/lru.h"

/** Maximal size of a cookie option. */
#define KR_COOKIE_OPT_MAX_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)

/**
 * Cookie option entry.
 */
struct cookie_opt_data {
	uint8_t opt_data[KR_COOKIE_OPT_MAX_LEN];
};

/**
 * DNS cookies tracking.
 */
typedef lru_hash(struct cookie_opt_data) kr_cookie_lru_t;

/**
 * @brief Obtain LRU cache entry.
 *
 * @param cache cookie LRU cache
 * @param sa socket address serving as key
 * @return pointer to cached option or NULL if not found or error occurred
 */
KR_EXPORT
const uint8_t *kr_cookie_lru_get(kr_cookie_lru_t *cache,
                                 const struct sockaddr *sa);

/**
 * @brief Stores cookie option into LRU cache.
 *
 * @param cache cookie LRU cache
 * @param sa socket address serving as key
 * @param opt cookie option to be stored
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_cookie_lru_set(kr_cookie_lru_t *cache, const struct sockaddr *sa,
                      uint8_t *opt);
