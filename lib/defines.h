/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <errno.h>
#include <libknot/errcode.h>
#include <libknot/dname.h>
#include <libknot/rrset.h>

/*
 * Error codes.
 */
#define kr_ok() 0
/* Mark as cold to mark all branches as unlikely. */
static inline int __attribute__((__cold__)) kr_error(int x) {
	return -abs(x);
}
#define kr_strerror(x) strerror(abs(x))

/*
 * Connection limits.
 * @cond internal
 */
#define KR_CONN_RTT_MAX 3000 /* Timeout for network activity */
#define KR_ITER_LIMIT 50     /* Built-in iterator limit */

/*
 * Defines.
 */
#define KR_DNS_PORT   53
#define KR_EDNS_VERSION 0
#define KR_EDNS_PAYLOAD 4096 /* Default UDP payload (max unfragmented UDP is 1452B) */

/*
 * Address sanitizer hints.
 */
#if !defined(__SANITIZE_ADDRESS__) && defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define __SANITIZE_ADDRESS__ 1
# endif
#endif
#if defined(__SANITIZE_ADDRESS__)
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#define kr_asan_poison(addr, size) __asan_poison_memory_region((addr), (size))
#define kr_asan_unpoison(addr, size) __asan_unpoison_memory_region((addr), (size))
#else
#define kr_asan_poison(addr, size)
#define kr_asan_unpoison(addr, size)
#endif
/* @endcond */