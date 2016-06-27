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

#include <netinet/in.h>

#include "lib/cache.h"

/** DNS cookie cache entry tag. */
#define KR_CACHE_COOKIE (KR_CACHE_USER + 'C')

/**
 * Peek the cache for asset (tag, socket address).
 * @note The 'drift' is the time passed between the inception time and now (in seconds).
 * @param cache cache structure
 * @param tag  asset tag
 * @param sa asset socket address
 * @param entry cache entry, will be set to valid pointer or NULL
 * @param timestamp current time (will be replaced with drift if successful)
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cookie_cache_peek(struct kr_cache *cache,
                         uint8_t tag, const struct sockaddr *sa,
                         struct kr_cache_entry **entry, uint32_t *timestamp);

/**
 * Insert asset into cache, replacing any existing data.
 * @param cache cache structure
 * @param tag  asset tag
 * @param sa asset socket address
 * @param header filled entry header (ttl and time stamp)
 * @param data inserted data
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cookie_cache_insert(struct kr_cache *cache,
                           uint8_t tag, const struct sockaddr *sa,
                           struct kr_cache_entry *header, knot_db_val_t data);

/**
 * Remove asset from cache.
 * @param cache cache structure
 * @param tag asset tag
 * @param sa asset socket address
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cookie_cache_remove(struct kr_cache *cache,
                           uint8_t tag, const struct sockaddr *sa);

/**
 * Structure used for cookie cache interface.
 * @note There is no other way how to pass a ttl into a cookie.
 */
struct timed_cookie {
	uint32_t ttl;
	const uint8_t *cookie_opt;
};

/**
 * Peek the cache for given cookie (socket address)
 * @note The 'drift' is the time passed between the cache time of the cookie and now (in seconds).
 * @param cache cache structure
 * @param sa socket address
 * @param cookie asset
 * @param timestamp current time (will be replaced with drift if successful)
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cookie_cache_peek_cookie(struct kr_cache *cache, const struct sockaddr *sa,
                                struct timed_cookie *cookie, uint32_t *timestamp);

/**
 * Insert a DNS cookie (client and server) entry for the given server signature (IP address).
 * @param cache cache structure
 * @param sa server IP address
 * @param cookie ttl and whole EDNS cookie option (header, client and server cookies)
 * @param timestamp current time
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cookie_cache_insert_cookie(struct kr_cache *cache, const struct sockaddr *sa,
                                  const struct timed_cookie *cookie,
                                  uint32_t timestamp);

/**
 * Remove asset from cache.
 * @param cache cache structure
 * @param sa socket address
 * @return 0 or an error code
 */
#define kr_cookie_cache_remove_cookie(cache, sa) \
	kr_cookie_cache_remove((cache), KR_CACHE_COOKIE, (sa))
