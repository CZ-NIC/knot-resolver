/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <netinet/in.h>
#include <stdint.h>

#if ENABLE_COOKIES
#include <libknot/rrtype/opt.h>
#include <libknot/rrtype/opt-cookie.h>
#else
#define KNOT_OPT_COOKIE_CLNT 8
#define KNOT_OPT_COOKIE_SRVR_MAX 32
#endif /* ENABLE_COOKIES */

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
typedef lru_t(struct cookie_opt_data) kr_cookie_lru_t;

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
