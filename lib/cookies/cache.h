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

#include "lib/cache.h"

#define KR_CACHE_COOKIE (KR_CACHE_USER + 'C')

KR_EXPORT
int kr_cookie_cache_peek(struct kr_cache_txn *txn, uint8_t tag, const void *sockaddr,
                         struct kr_cache_entry **entry, uint32_t *timestamp);

KR_EXPORT
int kr_cookie_cache_insert(struct kr_cache_txn *txn,
                           uint8_t tag, const void *sockaddr,
                           struct kr_cache_entry *header, knot_db_val_t data);

KR_EXPORT
int kr_cookie_cache_peek_cookie(struct kr_cache_txn *txn, const void *sockaddr,
                                const uint8_t **cookie_opt, uint32_t *timestamp);

/**
 * Insert a DNS cookie (client and server) entry for the given server signature (IP address).
 * @param txn transaction instance
 * @param sockaddr server IP address
 * @param cookie_opt whole EDNS cookie option (header, client and server)
 * @param cookie_size size of the cookie
 * @param timestamp current time
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cookie_cache_insert_cookie(struct kr_cache_txn *txn, const void *sockaddr,
                                  uint8_t *cookie_opt, uint32_t timestamp);
