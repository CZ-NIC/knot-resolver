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

#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <libknot/packet/pkt.h>
#include "lib/generic/map.h"
#include "lib/generic/array.h"
#include "lib/defines.h"

/*
 * Logging and debugging.
 */
#define kr_log_info(fmt, ...) printf((fmt), ## __VA_ARGS__)
#define kr_log_error(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__)
#ifndef NDEBUG
/* Toggle debug messages */
KR_EXPORT bool kr_debug_set(bool status);
KR_EXPORT KR_PURE bool kr_debug_status(void);
KR_EXPORT void kr_log_debug(const char *fmt, ...);
/* Debug block */
#define WITH_DEBUG if(__builtin_expect(kr_debug_status(), 0))
#else
#define kr_debug_status() false
#define kr_debug_set(x)
#define kr_log_debug(fmt, ...)
#define WITH_DEBUG if(0)
#endif

/** @cond Memory alloc routines */
static inline void *mm_alloc(knot_mm_t *mm, size_t size)
{
	if (mm) return mm->alloc(mm->ctx, size);
	else return malloc(size);
}
static inline void mm_free(knot_mm_t *mm, void *what)
{
	if (mm) { 
		if (mm->free)
			mm->free(what);
	}
	else free(what);
}
/* @endcond */

/** Return time difference in miliseconds.
  * @note based on the _BSD_SOURCE timersub() macro */
static inline long time_diff(struct timeval *begin, struct timeval *end) {
    struct timeval res = {
        .tv_sec = end->tv_sec - begin->tv_sec,
        .tv_usec = end->tv_usec - begin->tv_usec
    };
    if (res.tv_usec < 0) {
        --res.tv_sec;
        res.tv_usec += 1000000;
    }
    return res.tv_sec * 1000 + res.tv_usec / 1000;
}

/** @cond Array types */
struct kr_context;
typedef array_t(knot_rrset_t *) rr_array_t;
/* @endcond */

/** @internal RDATA array maximum size. */
#define RDATA_ARR_MAX (UINT16_MAX + sizeof(uint64_t))
/** @internal Next RDATA shortcut. */
#define kr_rdataset_next(rd) (rd + knot_rdata_array_size(knot_rdata_rdlen(rd)))

/** Concatenate N strings. */
KR_EXPORT
char* kr_strcatdup(unsigned n, ...);

/** Reseed CSPRNG context. */
int kr_rand_reseed(void);

/** Get pseudo-random value. */
KR_EXPORT
unsigned kr_rand_uint(unsigned max);

/** Memory reservation routine for knot_mm_t */
KR_EXPORT
int kr_memreserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have);

/** @internal Fast packet reset. */
KR_EXPORT
int kr_pkt_recycle(knot_pkt_t *pkt);

/** Construct and put record to packet. */
KR_EXPORT
int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen);

/** Address bytes for given family. */
KR_EXPORT KR_PURE
const char *kr_inaddr(const struct sockaddr *addr);
/** Address length for given family. */
KR_EXPORT KR_PURE
int kr_inaddr_len(const struct sockaddr *addr);
/** Return address type for string. */
KR_EXPORT KR_PURE
int kr_straddr_family(const char *addr);
/** Return address length in given family. */
KR_EXPORT KR_CONST
int kr_family_len(int family);
/** Parse address and return subnet length (bits).
  * @warning 'dst' must be at least `sizeof(struct in6_addr)` long. */
KR_EXPORT
int kr_straddr_subnet(void *dst, const char *addr);
/** Compare memory bitwise. */
KR_EXPORT KR_PURE
int kr_bitcmp(const char *a, const char *b, int bits);

/** @internal RR map flags. */
#define KEY_FLAG_RRSIG 0x02
#define KEY_FLAG_RANK(key) (key[0] >> 2)
#define KEY_COVERING_RRSIG(key) (key[0] & KEY_FLAG_RRSIG)

/* Stash key = {[1] flags, [1-255] owner, [5] type, [1] \x00 } */
#define KR_RRKEY_LEN (9 + KNOT_DNAME_MAXLEN)
/** Create unique null-terminated string key for RR.
  * @param key Destination buffer for key size, MUST be KR_RRKEY_LEN or larger.
  * @param owner RR owner domain name.
  * @param type RR type.
  * @param rank RR rank (8 bit tag usable for anything).
  * @return key length if successful or an error
  * */
KR_EXPORT
int kr_rrkey(char *key, const knot_dname_t *owner, uint16_t type, uint8_t rank);

/** @internal Merges RRSets with matching owner name and type together.
 * @note RRSIG RRSets are merged according the type covered fields.
 * @return 0 or an error
 */
int kr_rrmap_add(map_t *stash, const knot_rrset_t *rr, uint8_t rank, knot_mm_t *pool);

/** @internal Add RRSet copy to RR array. */
int kr_rrarray_add(rr_array_t *array, const knot_rrset_t *rr, knot_mm_t *pool);

/**
 * Call module property.
 */
KR_EXPORT
char *kr_module_call(struct kr_context *ctx, const char *module, const char *prop, const char *input);
