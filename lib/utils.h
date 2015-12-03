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
#include <sys/time.h>
#include <netinet/in.h>
#include <libknot/packet/pkt.h>
#include "lib/generic/map.h"
#include "lib/generic/array.h"

/*
 * General-purpose attributes.
 * @cond internal
 */
#define auto_free __attribute__((cleanup(_cleanup_free)))
extern void _cleanup_free(char **p);
#define auto_close __attribute__((cleanup(_cleanup_close)))
extern void _cleanup_close(int *p);
#define auto_fclose __attribute__((cleanup(_cleanup_fclose)))
extern void _cleanup_fclose(FILE **p);
/* @endcond */

/*
 * Logging and debugging.
 */
#define log_info(fmt, ...) printf((fmt), ## __VA_ARGS__)
#define log_error(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__)
#ifndef NDEBUG
extern bool _env_debug; /* @internal cond variable */
/* Toggle debug messages */
#define log_debug_enable(x) _env_debug = (x)
#define log_debug_status() _env_debug
/* Message logging */
#define log_debug(fmt, ...) do { \
    if (_env_debug) { printf((fmt), ## __VA_ARGS__); fflush(stdout); } \
    } while (0)
/* Debug block */
#define WITH_DEBUG if(__builtin_expect(_env_debug, 0))
#else
#define log_debug_status() false
#define log_debug_enable(x)
#define log_debug(fmt, ...)
#define WITH_DEBUG if(0)
#endif

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

/** @internal Next RDATA shortcut. */
#define kr_rdataset_next(rd) (rd + knot_rdata_array_size(knot_rdata_rdlen(rd)))

/** Concatenate N strings. */
char* kr_strcatdup(unsigned n, ...);

/** Reseed CSPRNG context. */
int kr_rand_reseed(void);

/** Get pseudo-random value. */
unsigned kr_rand_uint(unsigned max);

/** Memory reservation routine for mm_ctx_t */
int mm_reserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have);

/** @internal Fast packet reset. */
int kr_pkt_recycle(knot_pkt_t *pkt);

/** Construct and put record to packet. */
int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen);

/** Address bytes for given family. */
const char *kr_inaddr(const struct sockaddr *addr);
/** Address length for given family. */
int kr_inaddr_len(const struct sockaddr *addr);
/** Return address type for string. */
int kr_straddr_family(const char *addr);
/** Return address length in given family. */
int kr_family_len(int family);
/** Parse address and return subnet length (bits).
  * @warning 'dst' must be at least `sizeof(struct in6_addr)` long. */
int kr_straddr_subnet(void *dst, const char *addr);
/** Compare memory bitwise. */
int kr_bitcmp(const char *a, const char *b, int bits);

/** @internal RR map flags. */
#define KEY_FLAG_RRSIG 0x02
#define KEY_FLAG_RANK(key) (key[0] >> 2)
#define KEY_COVERING_RRSIG(key) (key[0] & KEY_FLAG_RRSIG)
/* Stash key = {[1] flags, [1-255] owner, [5] type, [1] \x00 } */
#define RRMAP_KEYSIZE (9 + KNOT_DNAME_MAXLEN)

/** @internal Create unique string key for RR. */
int kr_rrmap_key(char *key, const knot_dname_t *owner, uint16_t type, uint8_t rank);

/** @internal Merges RRSets with matching owner name and type together.
 * @note RRSIG RRSets are merged according the type covered fields.
 * @return 0 or an error
 */
int kr_rrmap_add(map_t *stash, const knot_rrset_t *rr, uint8_t rank, mm_ctx_t *pool);

/** @internal Add RRSet copy to RR array. */
int kr_rrarray_add(rr_array_t *array, const knot_rrset_t *rr, mm_ctx_t *pool);

/**
 * Call module property.
 */
char *kr_module_call(struct kr_context *ctx, const char *module, const char *prop, const char *input);
