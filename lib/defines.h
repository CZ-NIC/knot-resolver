/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <errno.h>
#include <libknot/errcode.h>
#include <libknot/dname.h>
#include <libknot/rrset.h>

/* Function attributes */
#if __GNUC__ >= 4
#define KR_EXPORT __attribute__ ((visibility ("default")))
#define KR_CONST __attribute__((__const__))
#define KR_PURE __attribute__((__pure__))
#define KR_NORETURN __attribute__((__noreturn__))
#define KR_COLD __attribute__((__cold__))
#define KR_PRINTF(n) __attribute__((format (printf, n, (n+1))))
#else
#define KR_EXPORT
#define KR_CONST
#define KR_PURE
#define KR_NORETURN
#define KR_COLD
#define KR_PRINTF(n)
#endif

#ifndef uint /* Redefining typedef is a C11 feature. */
typedef unsigned int uint;
#define uint uint
#endif

/*
 * Error codes.
 */
#define kr_ok() 0
/* Mark as cold to mark all branches as unlikely. */
static inline int KR_COLD kr_error(int x) {
    return x <= 0 ? x : -x;
}
#define kr_strerror(x) strerror(abs(x))

/*
 * Connection limits.
 * @cond internal
 */
#define KR_CONN_RTT_MAX 2000 /* Timeout for network activity */
#define KR_CONN_RETRY 200    /* Retry interval for network activity */
#define KR_ITER_LIMIT 100    /* Built-in iterator limit */
#define KR_RESOLVE_TIME_LIMIT 10000 /* Upper limit for resolution time of single query, ms */
#define KR_CNAME_CHAIN_LIMIT 13 /* Built-in maximum CNAME chain length */
#define KR_TIMEOUT_LIMIT 10   /* Maximum number of retries after timeout. */
#define KR_QUERY_NSRETRY_LIMIT 4 /* Maximum number of retries per query. */
#define KR_COUNT_NO_NSADDR_LIMIT 5
#define KR_CONSUME_FAIL_ROW_LIMIT 3 /* Maximum number of KR_STATE_FAIL in a row. */

/*
 * Defines.
 */
#define KR_DNS_PORT   53
#define KR_DNS_DOH_PORT 443
#define KR_DNS_TLS_PORT 853
#define KR_EDNS_VERSION 0
#define KR_EDNS_PAYLOAD 1232 /* Default UDP payload; see https://dnsflagday.net/2020/ */
#define KR_CACHE_DEFAULT_TTL_MIN (5) /* avoid bursts of queries */
#define KR_CACHE_DEFAULT_TTL_MAX (6 * 24 * 3600) /* 6 days, like the root NS TTL */

#define KR_DNAME_STR_MAXLEN (KNOT_DNAME_TXT_MAXLEN + 1)
#define KR_RRTYPE_STR_MAXLEN (16 + 1)

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
#define kr_asan_custom_poison(fn, addr) fn ##_poison((addr))
#define kr_asan_custom_unpoison(fn, addr) fn ##_unpoison((addr))
#else
#define kr_asan_poison(addr, size)
#define kr_asan_unpoison(addr, size)
#define kr_asan_custom_poison(fn, addr)
#define kr_asan_custom_unpoison(fn, addr)
#endif

#if defined(__SANITIZE_ADDRESS__) && defined(_FORTIFY_SOURCE)
	#error "You can't use address sanitizer with _FORTIFY_SOURCE"
	// https://github.com/google/sanitizers/issues/247
#endif

/* @endcond */
