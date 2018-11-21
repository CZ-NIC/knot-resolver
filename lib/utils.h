/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <libknot/libknot.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>
#include <lua.h>
#include "lib/generic/array.h"
#include "lib/defines.h"

struct kr_query;
struct kr_request;

/*
 * Logging and debugging.
 */

/** @brief Callback for request events. */
typedef void (*trace_callback_f)(struct kr_request *request);
/** @brief Callback for request logging handler. */
typedef void (*trace_log_f)(const struct kr_query *query, const char *source, const char *msg);

#define kr_log_info(fmt, ...) do { printf((fmt), ## __VA_ARGS__); fflush(stdout); } while(0)
#define kr_log_error(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__)

/* Always export these, but override direct calls by macros conditionally. */
/** Whether in --verbose mode.  Only use this for reading. */
KR_EXPORT extern bool kr_verbose_status;

/** Set --verbose mode.  Not available if compiled with -DNOVERBOSELOG. */
KR_EXPORT bool kr_verbose_set(bool status);

/** Log a message if in --verbose mode. */
KR_EXPORT KR_PRINTF(1)
void kr_log_verbose(const char *fmt, ...);

/**
 * @brief Return true if the query has request log handler installed.
 */
#define kr_log_trace_enabled(query) ((query) && (query)->request && (query)->request->trace_log)

/**
 * Log a message through the request log handler.
 * @param  query current query
 * @param  source message source
 * @param  fmt message format
 * @return true if the message was logged
 */
KR_EXPORT KR_PRINTF(3)
bool kr_log_trace(const struct kr_query *query, const char *source, const char *fmt, ...);

#ifdef NOVERBOSELOG
/* Efficient compile-time disabling of verbose messages. */
#define kr_verbose_status false
#define kr_verbose_set(x)
#endif

/** Block run in --verbose mode; optimized when not run. */
#define VERBOSE_STATUS __builtin_expect(kr_verbose_status, false)
#define WITH_VERBOSE(query) if(__builtin_expect(kr_verbose_status || kr_log_trace_enabled(query), false))
#define kr_log_verbose if(VERBOSE_STATUS) kr_log_verbose

#define KR_DNAME_GET_STR(dname_str, dname) \
	char dname_str[KR_DNAME_STR_MAXLEN]; \
	knot_dname_to_str(dname_str, (dname), sizeof(dname_str)); \
	dname_str[sizeof(dname_str) - 1] = 0;

#define KR_RRTYPE_GET_STR(rrtype_str, rrtype) \
	char rrtype_str[KR_RRTYPE_STR_MAXLEN]; \
	knot_rrtype_to_string((rrtype), rrtype_str, sizeof(rrtype_str)); \
	rrtype_str[sizeof(rrtype_str) - 1] = 0;

/* C11 compatibility, but without any implementation so far. */
#ifndef static_assert
#define static_assert(cond, msg)
#endif

/** @cond Memory alloc routines */
static inline void *mm_alloc(knot_mm_t *mm, size_t size)
{
	if (mm) return mm->alloc(mm->ctx, size);
	else return malloc(size);
}
static inline void mm_free(knot_mm_t *mm, const void *what)
{
	if (mm) {
		if (mm->free)
			mm->free((void *)what);
	}
	else free((void *)what);
}
static inline void *mm_realloc(knot_mm_t *mm, void *what, size_t size, size_t prev_size)
{
	if (mm) {
		void *p = mm->alloc(mm->ctx, size);
		if (p == NULL) {
			return NULL;
		} else {
			if (what) {
				memcpy(p, what,
				       prev_size < size ? prev_size : size);
			}
			mm_free(mm, what);
			return p;
		}
	} else {
		return realloc(what, size);
	}
}

/** Trivial malloc() wrapper. */
void *mm_malloc(void *ctx, size_t n);

/** Initialize mm with standard malloc+free. */
static inline void mm_ctx_init(knot_mm_t *mm)
{
	mm->ctx = NULL;
	mm->alloc = mm_malloc;
	mm->free = free;
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

/** @cond internal Array types */
struct kr_context;

typedef array_t(knot_rrset_t *) rr_array_t;
struct ranked_rr_array_entry {
	uint32_t qry_uid;
	uint8_t rank; /**< enum kr_rank */
	uint8_t revalidation_cnt;
	bool cached : 1;  /**< Set to true if the entry was written into cache */
	bool yielded : 1;
	bool to_wire : 1; /**< whether to be put into the answer */
	bool expiring : 1; /**< low remaining TTL; see is_expiring; only used in cache ATM */
	knot_rrset_t *rr;
};
typedef struct ranked_rr_array_entry ranked_rr_array_entry_t;

/** Array of RRsets coming from multiple queries; for struct kr_request.
 *
 * Notes:
 *  - RRSIGs are only considered to form an RRset when the types covered match;
 *    cache-related code relies on that!
 *  - RRsets from the same packet (qry_uid) get merged.
 */
typedef array_t(ranked_rr_array_entry_t *) ranked_rr_array_t;
/* @endcond */

/** @internal RDATA array maximum size. */
#define RDATA_ARR_MAX (UINT16_MAX + sizeof(uint64_t))

/** Concatenate N strings. */
KR_EXPORT
char* kr_strcatdup(unsigned n, ...);

/** Reseed CSPRNG context. */
int kr_rand_reseed(void);

/** Get pseudo-random value between zero and max-1 (inclusive).
 *
 * Passing zero means that any uint32_t should be returned (it's also faster).
 */
KR_EXPORT
uint32_t kr_rand_uint(uint32_t max);

/** Memory reservation routine for knot_mm_t */
KR_EXPORT
int kr_memreserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have);

/** @internal Fast packet reset. */
KR_EXPORT
int kr_pkt_recycle(knot_pkt_t *pkt);

/** @internal Clear packet payload. */
KR_EXPORT
int kr_pkt_clear_payload(knot_pkt_t *pkt);

/** Construct and put record to packet. */
KR_EXPORT
int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen);

/** Set packet header suitable for authoritative answer. (for policy module) */
KR_EXPORT
void kr_pkt_make_auth_header(knot_pkt_t *pkt);

/** Simple storage for IPx address or AF_UNSPEC. */
union inaddr {
	struct sockaddr ip;
	struct sockaddr_in ip4;
	struct sockaddr_in6 ip6;
};

/** Address bytes for given family. */
KR_EXPORT KR_PURE
const char *kr_inaddr(const struct sockaddr *addr);
/** Address family. */
KR_EXPORT KR_PURE
int kr_inaddr_family(const struct sockaddr *addr);
/** Address length for given family, i.e. sizeof(struct in*_addr). */
KR_EXPORT KR_PURE
int kr_inaddr_len(const struct sockaddr *addr);
/** Sockaddr length for given family, i.e. sizeof(struct sockaddr_in*). */
KR_EXPORT KR_PURE
int kr_sockaddr_len(const struct sockaddr *addr);
/** Compare two given sockaddr.
 * return 0 - addresses are equal, error code otherwise.
 */
KR_EXPORT KR_PURE
int kr_sockaddr_cmp(const struct sockaddr *left, const struct sockaddr *right);
/** Port. */
KR_EXPORT KR_PURE
uint16_t kr_inaddr_port(const struct sockaddr *addr);
/** Set port. */
KR_EXPORT
void kr_inaddr_set_port(struct sockaddr *addr, uint16_t port);
/** String representation for given address as "<addr>#<port>" */
KR_EXPORT
int kr_inaddr_str(const struct sockaddr *addr, char *buf, size_t *buflen);
/** Return address type for string. */
KR_EXPORT KR_PURE
int kr_straddr_family(const char *addr);
/** Return address length in given family (struct in*_addr). */
KR_EXPORT KR_CONST
int kr_family_len(int family);
/** Create a sockaddr* from string+port representation (also accepts IPv6 link-local). */
KR_EXPORT
struct sockaddr * kr_straddr_socket(const char *addr, int port);
/** Parse address and return subnet length (bits).
  * @warning 'dst' must be at least `sizeof(struct in6_addr)` long. */
KR_EXPORT
int kr_straddr_subnet(void *dst, const char *addr);

/** Splits ip address specified as "addr@port" or "addr#port" into addr and port
  * and performs validation.
  * @note if #port part isn't present, then port will be set to 0.
  *       buf and\or port can be set to NULL.
  * @return kr_error(EINVAL) - addr part doesn't contains valid ip address or
  *                            #port part is out-of-range (either < 0 either > UINT16_MAX)
  *         kr_error(ENOSP)  - buflen is too small
  */
KR_EXPORT
int kr_straddr_split(const char *addr, char *buf, size_t buflen, uint16_t *port);
/** Formats ip address and port in "addr#port" format.
  * and performs validation.
  * @note Port always formatted as five-character string with leading zeros.
  * @return kr_error(EINVAL) - addr or buf is NULL or buflen is 0 or
  *                            addr doesn't contain a valid ip address
  *         kr_error(ENOSP)  - buflen is too small
  */
KR_EXPORT
int kr_straddr_join(const char *addr, uint16_t port, char *buf, size_t *buflen);

/** Compare memory bitwise.  The semantics is "the same" as for memcmp().
 *  The partial byte is considered with more-significant bits first,
 *  so this is e.g. suitable for comparing IP prefixes. */
KR_EXPORT KR_PURE
int kr_bitcmp(const char *a, const char *b, int bits);

/** @internal RR map flags. */
static const uint8_t KEY_FLAG_RRSIG = 0x02;
static inline uint8_t KEY_FLAG_RANK(const char *key)
	{ return ((uint8_t)(key[0])) >> 2; }
static inline bool KEY_COVERING_RRSIG(const char *key)
	{ return ((uint8_t)(key[0])) & KEY_FLAG_RRSIG; }

/* Stash key = {[5] class, [1-255] owner, [5] type, [5] additional, [1] \x00 } */
#define KR_RRKEY_LEN (16 + KNOT_DNAME_MAXLEN)
/** Create unique null-terminated string key for RR.
  * @param key Destination buffer for key size, MUST be KR_RRKEY_LEN or larger.
  * @param class RR class.
  * @param owner RR owner name.
  * @param type RR type.
  * @param additional flags (for instance can be used for storing covered type
  *	   when RR type is RRSIG).
  * @return key length if successful or an error
  * */
KR_EXPORT
int kr_rrkey(char *key, uint16_t class, const knot_dname_t *owner,
	     uint16_t type, uint16_t additional);

/** @internal Add RRSet copy to ranked RR array. */
KR_EXPORT
int kr_ranked_rrarray_add(ranked_rr_array_t *array, const knot_rrset_t *rr,
			  uint8_t rank, bool to_wire, uint32_t qry_uid, knot_mm_t *pool);

/** @internal Mark the RRSets from particular query as
 * "have (not) to be recorded in the final answer".
 * @param array RRSet array.
 * @param to_wire Records must be\must not be recorded in final answer.
 * @param qry_uid Query uid.
 * @param check_dups When to_wire is true, try to avoid duplicate RRSets.
 * @param extraCheck optional function checking whether to consider the record
 * @return 0 or an error
 */
int kr_ranked_rrarray_set_wire(ranked_rr_array_t *array, bool to_wire,
			       uint32_t qry_uid, bool check_dups,
			       bool (*extraCheck)(const ranked_rr_array_entry_t *));

KR_PURE
char *kr_pkt_text(const knot_pkt_t *pkt);

KR_PURE
char *kr_rrset_text(const knot_rrset_t *rr);

KR_PURE
static inline char *kr_dname_text(const knot_dname_t *name) {
	return knot_dname_to_str_alloc(name);
}

KR_CONST
static inline char *kr_rrtype_text(const uint16_t rrtype) {
	char type_str[32] = {0};
	knot_rrtype_to_string(rrtype, type_str, sizeof(type_str));
	return strdup(type_str);
}

/**
 * Call module property.
 */
KR_EXPORT
char *kr_module_call(struct kr_context *ctx, const char *module, const char *prop, const char *input);

/** Swap two places.  Note: the parameters need to be without side effects. */
#define SWAP(x, y) do { /* http://stackoverflow.com/a/3982430/587396 */ \
	unsigned char swap_temp[sizeof(x) == sizeof(y) ? (ssize_t)sizeof(x) : -1]; \
	memcpy(swap_temp, &y, sizeof(x)); \
	memcpy(&y,        &x, sizeof(x)); \
	memcpy(&x, swap_temp, sizeof(x)); \
	} while(0)

/** Return the (covered) type of an nonempty RRset. */
static inline uint16_t kr_rrset_type_maysig(const knot_rrset_t *rr)
{
	assert(rr && rr->rrs.count && rr->rrs.rdata);
	uint16_t type = rr->type;
	if (type == KNOT_RRTYPE_RRSIG)
		type = knot_rrsig_type_covered(rr->rrs.rdata);
	return type;
}

/** Printf onto the lua stack, avoiding additional copy (thin wrapper). */
KR_PRINTF(2)
static inline const char *lua_push_printf(lua_State *L, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	const char *ret = lua_pushvfstring(L, fmt, args);
	va_end(args);
	return ret;
}

/** @internal Return string representation of addr.
 *  @note return pointer to static string
 */
static inline char *kr_straddr(const struct sockaddr *addr)
{
	assert(addr != NULL);
	/* We are the sinle-threaded application */
	static char str[INET6_ADDRSTRLEN + 1 + 5 + 1];
	size_t len = sizeof(str);
	int ret = kr_inaddr_str(addr, str, &len);
	return ret != kr_ok() || len == 0 ? NULL : str;
}

/** The current time in monotonic milliseconds.
 *
 * \note it may be outdated in case of long callbacks; see uv_now().
 */
KR_EXPORT
uint64_t kr_now();

/** Convert name from lookup format to wire.  See knot_dname_lf
 *
 * \note len bytes are read and len+1 are written with *normal* LF,
 * 	 but it's also allowed that the final zero byte is omitted in LF.
 * \return the number of bytes written (>0) or error code (<0)
 */
int knot_dname_lf2wire(knot_dname_t *dst, uint8_t len, const uint8_t *lf);

/** Patched knot_dname_lf.  LF for "." has length zero instead of one, for consistency.
 * (TODO: consistency?)
 * \param add_wildcard append the wildcard label
 * \note packet is always NULL
 */
static inline int kr_dname_lf(uint8_t *dst, const knot_dname_t *src, bool add_wildcard)
{
	knot_dname_storage_t right_aligned_dst;
	uint8_t *right_aligned_dname_start = knot_dname_lf(src, right_aligned_dst);
	if (!right_aligned_dname_start) {
		return kr_error(EINVAL);
	}
	int len = right_aligned_dname_start[0];
	assert(right_aligned_dname_start + 1 + len - KNOT_DNAME_MAXLEN == right_aligned_dst);
	memcpy(dst + 1, right_aligned_dname_start + 1, len);
	if (add_wildcard) {
		if (len + 2 > KNOT_DNAME_MAXLEN)
			return kr_error(ENOSPC);
		dst[len + 1] = '*';
		dst[len + 2] = '\0';
		len += 2;
	}
	dst[0] = len;
	return KNOT_EOK;
}

/* Trivial non-inline wrappers, to be used in lua. */
KR_EXPORT void kr_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
				uint16_t type, uint16_t rclass, uint32_t ttl);
KR_EXPORT uint16_t kr_pkt_qclass(const knot_pkt_t *pkt);
KR_EXPORT uint16_t kr_pkt_qtype(const knot_pkt_t *pkt);
KR_EXPORT uint32_t kr_rrsig_sig_inception(const knot_rdata_t *rdata);
KR_EXPORT uint32_t kr_rrsig_sig_expiration(const knot_rdata_t *rdata);
KR_EXPORT uint16_t kr_rrsig_type_covered(const knot_rdata_t *rdata);
