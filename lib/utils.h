/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <libknot/libknot.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>
#include <uv.h>

#include "kresconfig.h"
#include "contrib/mempattern.h"
#include "lib/defines.h"
#include "lib/generic/array.h"

struct kr_query;
struct kr_request;

/*
 * Logging and debugging.
 */

/** @brief Callback for request events. */
typedef void (*trace_callback_f)(struct kr_request *request);
/**
 * @brief Callback for request logging handler.
 * @param[in] msg Log message. Pointer is not valid after handler returns. */
typedef void (*trace_log_f)(const struct kr_request *request, const char *msg);

#define kr_log_info printf
#define kr_log_error(...) fprintf(stderr, ## __VA_ARGS__)
#define kr_log_critical(...) kr_log_error(__VA_ARGS__)
#define kr_log_deprecate(...) fprintf(stderr, "deprecation WARNING: " __VA_ARGS__)

#define kr_require(cond)                                                      \
	do {                                                                  \
		if (!__builtin_expect((cond), true)) {                        \
			kr_log_critical("requirement failed in %s@%s:%d\n",   \
				__func__, __FILE__, __LINE__);                \
			abort();                                              \
		}                                                             \
	} while (0)
#define kr_assume_else(cond, else_expr)                                       \
	do {                                                                  \
		if (!__builtin_expect((cond), true)) {                        \
			kr_log_error("assumption failed in %s@%s:%d\n",       \
				__func__, __FILE__, __LINE__);                \
			if (kr_debug_assumption && fork() == 0) abort();      \
			else_expr;                                            \
		}                                                             \
	} while (0)
#define kr_assume(cond) kr_assume((cond), return kr_error(EINVAL))

/* Always export these, but override direct calls by macros conditionally. */
/** Whether in --verbose mode.  Only use this for reading. */
KR_EXPORT extern bool kr_verbose_status;

/** Set --verbose mode.  Not available if compiled with -DNOVERBOSELOG. */
KR_EXPORT bool kr_verbose_set(bool status);

/** Whether kr_assume() checks should result fork and abort. */
KR_EXPORT extern bool kr_debug_assumption;

/**
 * @brief Return true if the query has request log handler installed.
 */
#define kr_log_rtrace_enabled(req) (__builtin_expect( \
	(req) && (req)->trace_log, \
	false))

#define kr_log_qtrace_enabled(qry) (__builtin_expect( \
	(qry) && kr_log_rtrace_enabled(qry->request), \
	false))

/**
 * Log a message through the request log handler or stdout.
 * Caller is responsible for detecting verbose mode, use QRVERBOSE() macro.
 * @param  qry_uid query ID to append to request ID, 0 means "no query"
 * @param  indent level of indentation between [req.qry][source] and message
 * @param  source message source
 * @param  fmt message format
 */
KR_EXPORT KR_PRINTF(5)
void kr_log_req(const struct kr_request * const req, uint32_t qry_uid,
		const unsigned int indent, const char *source, const char *fmt, ...);

/**
 * Log a message through the request log handler or stdout.
 * Caller is responsible for detecting verbose mode, use QRVERBOSE() macro.
 * @param  qry current query
 * @param  source message source
 * @param  fmt message format
 */
KR_EXPORT KR_PRINTF(3)
void kr_log_q(const struct kr_query *qry, const char *source, const char *fmt, ...);

#ifdef NOVERBOSELOG
/* Efficient compile-time disabling of verbose messages. */
#define kr_verbose_status false
#define kr_verbose_set(x)
#endif

/** Block run in --verbose mode; optimized when not run. */
#define VERBOSE_STATUS __builtin_expect(kr_verbose_status, false)
#define WITH_VERBOSE(query) if(__builtin_expect(kr_verbose_status || kr_log_qtrace_enabled(query), false))
#define kr_log_verbose if(VERBOSE_STATUS) printf

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

// Use this for alocations with mm.
// Use mm_alloc for alocations into mempool

/** A strcmp() variant directly usable for qsort() on an array of strings. */
static inline int strcmp_p(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, *(char * const *)p2);
}


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

/** Get current working directory with fallback value. */
static inline void get_workdir(char *out, size_t len) {
	if(getcwd(out, len) == NULL) {
		static const char errprefix[] = "<invalid working directory>";
		strncpy(out, errprefix, len);
	}
}

/** @cond internal Array types */
struct kr_context;

struct ranked_rr_array_entry {
	uint32_t qry_uid;
	uint8_t rank; /**< enum kr_rank */
	uint8_t revalidation_cnt;
	bool cached : 1;  /**< Set to true if the entry was written into cache */
	bool yielded : 1;
	bool to_wire : 1; /**< whether to be put into the answer */
	bool expiring : 1; /**< low remaining TTL; see is_expiring; only used in cache ATM */
	bool in_progress : 1; /**< build of RRset in progress, i.e. different format of RR data */
	bool dont_cache : 1; /**< avoid caching; useful e.g. for generated data */
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

/** Concatenate N strings. */
KR_EXPORT
char* kr_strcatdup(unsigned n, ...);

/** Construct absolute file path, without resolving symlinks.
 * \return malloc-ed string or NULL (+errno in that case) */
KR_EXPORT
char * kr_absolutize_path(const char *dirname, const char *fname);

/** You probably want kr_rand_* convenience functions instead.
 * This is a buffered version of gnutls_rnd(GNUTLS_RND_NONCE, ..) */
KR_EXPORT
void kr_rnd_buffered(void *data, unsigned int size);

/** Return a few random bytes. */
static inline uint64_t kr_rand_bytes(unsigned int size)
{
	uint64_t result;
	if (size <= 0 || size > sizeof(result)) {
		kr_log_error("kr_rand_bytes(): EINVAL\n");
		abort();
	}
	uint8_t data[sizeof(result)];
	kr_rnd_buffered(data, size);
	/* I would have liked to dump the random data into a size_t directly,
	 * but that would work well only on little-endian machines,
	 * so instead I hope that the compiler will optimize this out.
	 * (Tested via reading assembly from usual gcc -O2 setup.)
	 * Alternatively we could waste more rnd bytes, but that seemed worse. */
	result = 0;
	for (unsigned int i = 0; i < size; ++ i) {
		result |= ((size_t)data[i]) << (i * 8);
	}
	return result;
}

/** Throw a pseudo-random coin, succeeding approximately with probability nomin/denomin.
 * - low precision, only one byte of randomness (or none with extreme parameters)
 * - tip: use !kr_rand_coin() to get the complementary probability
 */
static inline bool kr_rand_coin(unsigned int nomin, unsigned int denomin)
{
	/* This function might be called with non-constant values
	 * so we try to handle odd corner cases instead of crash. */
	if (nomin >= denomin)
		return true;
	else if (nomin <= 0)
		return false;

	/* threshold = how many parts from 256 are a success */
	unsigned int threshold = (nomin * 256 + /*rounding*/ denomin / 2) / denomin;
	if (threshold == 0) threshold = 1;
	if (threshold == 256) threshold = 255;
	return (kr_rand_bytes(1) < threshold);
}

/** Memory reservation routine for knot_mm_t */
KR_EXPORT
int kr_memreserve(void *baton, void **mem, size_t elm_size, size_t want, size_t *have);

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

/** Write string representation for given address as "<addr>#<port>".
 * \param[in]     addr   the raw address
 * \param[out]    buf    the buffer for output string
 * \param[in,out] buflen the available(in) and utilized(out) length, including \0 */
KR_EXPORT
int kr_inaddr_str(const struct sockaddr *addr, char *buf, size_t *buflen);

/** Write string representation for given address as "<addr>#<port>".
 * It's the same as kr_inaddr_str(), but the input address is input in native format
 * like for inet_ntop() (4 or 16 bytes) and port must be separate parameter.  */
KR_EXPORT
int kr_ntop_str(int family, const void *src, uint16_t port, char *buf, size_t *buflen);

/** @internal Create string representation addr#port.
 *  @return pointer to static string
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


/** Return address type for string. */
KR_EXPORT KR_PURE
int kr_straddr_family(const char *addr);
/** Return address length in given family (struct in*_addr). */
KR_EXPORT KR_CONST
int kr_family_len(int family);

/** Create a sockaddr* from string+port representation.
 * Also accepts IPv6 link-local and AF_UNIX starting with "/" (ignoring port) */
KR_EXPORT
struct sockaddr * kr_straddr_socket(const char *addr, int port, knot_mm_t *pool);

/** Parse address and return subnet length (bits).
  * @warning 'dst' must be at least `sizeof(struct in6_addr)` long. */
KR_EXPORT
int kr_straddr_subnet(void *dst, const char *addr);

/** Splits ip address specified as "addr@port" or "addr#port" into addr and port.
 * \param[in]  instr zero-terminated input, e.g. "192.0.2.1#12345\0"
 * \param[out] ipaddr working buffer for the port-less prefix of instr;
 *                    length >= INET6_ADDRSTRLEN + 1.
 * \param[out] port written in case it's specified in instr
 * \return error code
 * \note Typically you follow this by kr_straddr_socket().
 * \note Only internet addresses are supported, i.e. no AF_UNIX sockets.
 */
KR_EXPORT
int kr_straddr_split(const char *instr, char ipaddr[static restrict (INET6_ADDRSTRLEN + 1)],
		     uint16_t *port);

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

/** Add RRSet copy to a ranked RR array.
 *
 * To convert to standard RRs inside, you need to call _finalize() afterwards,
 * and the memory of rr->rrs.rdata has to remain until then.
 *
 * \return array index (>= 0) or error code (< 0)
 */
KR_EXPORT
int kr_ranked_rrarray_add(ranked_rr_array_t *array, const knot_rrset_t *rr,
			  uint8_t rank, bool to_wire, uint32_t qry_uid, knot_mm_t *pool);
/** Finalize in_progress sets - all with matching qry_uid. */
KR_EXPORT
int kr_ranked_rrarray_finalize(ranked_rr_array_t *array, uint32_t qry_uid, knot_mm_t *pool);

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

/**
 * @return Newly allocated string representation of packet.
 * Caller has to free() returned string.
 */
KR_EXPORT
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

/** The current time in monotonic milliseconds.
 *
 * \note it may be outdated in case of long callbacks; see uv_now().
 */
KR_EXPORT
uint64_t kr_now();

/** Call free(handle->data); it's useful e.g. as a callback in uv_close(). */
KR_EXPORT void kr_uv_free_cb(uv_handle_t* handle);

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

/**
 * Difference between two calendar times specified as strings.
 * \param[in]  format format for strptime
 * \param[out] diff result from C difftime(time1, time0)
 */
KR_EXPORT
const char *kr_strptime_diff(const char *format, const char *time1_str,
		             const char *time0_str, double *diff);

/* Trivial non-inline wrappers, to be used in lua. */
KR_EXPORT void kr_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
				uint16_t type, uint16_t rclass, uint32_t ttl);
KR_EXPORT uint16_t kr_pkt_has_dnssec(const knot_pkt_t *pkt);
KR_EXPORT uint16_t kr_pkt_qclass(const knot_pkt_t *pkt);
KR_EXPORT uint16_t kr_pkt_qtype(const knot_pkt_t *pkt);
KR_EXPORT uint32_t kr_rrsig_sig_inception(const knot_rdata_t *rdata);
KR_EXPORT uint32_t kr_rrsig_sig_expiration(const knot_rdata_t *rdata);
KR_EXPORT uint16_t kr_rrsig_type_covered(const knot_rdata_t *rdata);

KR_EXPORT time_t kr_file_mtime (const char* fname);
/** Return filesystem size in bytes. */
KR_EXPORT long long kr_fssize(const char *path);
/** Simply return de->dname. (useful from Lua) */
KR_EXPORT const char * kr_dirent_name(const struct dirent *de);

