/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <libknot/packet/pkt.h>

#include "lib/cookies/control.h"
#include "lib/cookies/lru_cache.h"
#include "lib/layer.h"
#include "lib/generic/array.h"
#include "lib/selection.h"
#include "lib/rplan.h"
#include "lib/module.h"
#include "lib/cache/api.h"

/**
 * @file resolve.h
 * @brief The API provides an API providing a "consumer-producer"-like interface to enable
 * user to plug it into existing event loop or I/O code.
 *
 * # Example usage of the iterative API:
 *
 * @code{.c}
 *
 * // Create request and its memory pool
 * struct kr_request req = {
 * 	.pool = {
 * 		.ctx = mp_new (4096),
 * 		.alloc = (mm_alloc_t) mp_alloc
 * 	}
 * };
 *
 * // Setup and provide input query
 * int state = kr_resolve_begin(&req, ctx);
 * state = kr_resolve_consume(&req, query);
 *
 * // Generate answer
 * while (state == KR_STATE_PRODUCE) {
 *
 *     // Additional query generate, do the I/O and pass back answer
 *     state = kr_resolve_produce(&req, &addr, &type, query);
 *     while (state == KR_STATE_CONSUME) {
 *         int ret = sendrecv(addr, proto, query, resp);
 *
 *         // If I/O fails, make "resp" empty
 *         state = kr_resolve_consume(&request, addr, resp);
 *         knot_pkt_clear(resp);
 *     }
 *     knot_pkt_clear(query);
 * }
 *
 * // "state" is either DONE or FAIL
 * kr_resolve_finish(&request, state);
 *
 * @endcode
 */


struct kr_request;
/** Allocate buffer for answer's wire (*maxlen may get lowered).
 *
 * Motivation: XDP wire allocation is an overlap of library and daemon:
 *  - it needs to be called from the library
 *  - it needs to rely on some daemon's internals
 *  - the library (currently) isn't allowed to directly use symbols from daemon
 *    (contrary to modules), e.g. some of our lib-using tests run without daemon
 *
 * Note: after we obtain the wire, we're obliged to send it out.
 * (So far there's no use case to allow cancelling at that point.)
 */
typedef uint8_t * (*alloc_wire_f)(struct kr_request *req, uint16_t *maxlen);

/**
 * RRset rank - for cache and ranked_rr_*.
 *
 * The rank meaning consists of one independent flag - KR_RANK_AUTH,
 * and the rest have meaning of values where only one can hold at any time.
 * You can use one of the enums as a safe initial value, optionally | KR_RANK_AUTH;
 * otherwise it's best to manipulate ranks via the kr_rank_* functions.
 *
 * @note The representation is complicated by restrictions on integer comparison:
 * - AUTH must be > than !AUTH
 * - AUTH INSECURE must be > than AUTH (because it attempted validation)
 * - !AUTH SECURE must be > than AUTH (because it's valid)
 *
 * See also:
 *   https://tools.ietf.org/html/rfc2181#section-5.4.1
 *   https://tools.ietf.org/html/rfc4035#section-4.3
 */
enum kr_rank {
	/* Initial-like states.  No validation has been attempted (yet). */
	KR_RANK_INITIAL = 0, /**< Did not attempt to validate. It's assumed
					compulsory to validate (or prove insecure). */
	KR_RANK_OMIT,        /**< Do not attempt to validate.
					(And don't consider it a validation failure.) */
	KR_RANK_TRY,         /**< Attempt to validate, but failures are non-fatal. */

	/* Failure states.  These have higher value because they have more information. */
	KR_RANK_INDET = 4,   /**< Unable to determine whether it should be secure. */
	KR_RANK_BOGUS,       /**< Ought to be secure but isn't. */
	KR_RANK_MISMATCH,
	KR_RANK_MISSING,     /**< No RRSIG found for that owner+type combination. */

	/** Proven to be insecure, i.e. we have a chain of trust from TAs
	 * that cryptographically denies the possibility of existence
	 * of a positive chain of trust from the TAs to the record.
	 * Or it may be covered by a closer negative TA. */
	KR_RANK_INSECURE = 8,

	/** Authoritative data flag; the chain of authority was "verified".
	 *  Even if not set, only in-bailiwick stuff is acceptable,
	 *  i.e. almost authoritative (example: mandatory glue and its NS RR). */
	KR_RANK_AUTH = 16,

	KR_RANK_SECURE = 32,  /**< Verified whole chain of trust from the closest TA. */
	/* @note Rank must not exceed 6 bits */
};

/** Check that a rank value is valid.  Meant for assertions. */
bool kr_rank_check(uint8_t rank) KR_PURE;

/** Test the presence of any flag/state in a rank, i.e. including KR_RANK_AUTH. */
bool kr_rank_test(uint8_t rank, uint8_t kr_flag) KR_PURE KR_EXPORT;

/** Set the rank state. The _AUTH flag is kept as it was. */
static inline void kr_rank_set(uint8_t *rank, uint8_t kr_flag)
{
	if (kr_fails_assert(rank && kr_rank_check(*rank)))
		return;
	if (kr_fails_assert(kr_rank_check(kr_flag) && !(kr_flag & KR_RANK_AUTH)))
		return;
	*rank = kr_flag | (*rank & KR_RANK_AUTH);
}


/** @cond internal Array of modules. */
typedef array_t(struct kr_module *) module_array_t;
/* @endcond */

/**
 * Name resolution context.
 *
 * Resolution context provides basic services like cache, configuration and options.
 *
 * @note This structure is persistent between name resolutions and may
 *       be shared between threads.
 */
struct kr_context
{
	/** Default kr_request flags.  For startup defaults see init_resolver() */
	struct kr_qflags options;

	/** Default EDNS towards *both* clients and upstream.
	 * LATER: consider splitting the two, e.g. allow separately
	 * configured limits for UDP packet size (say, LAN is under control). */
	knot_rrset_t *downstream_opt_rr;
	knot_rrset_t *upstream_opt_rr;

	trie_t *trust_anchors;
	trie_t *negative_anchors;
	struct kr_zonecut root_hints;
	struct kr_cache cache;
	unsigned cache_rtt_tout_retry_interval;
	module_array_t *modules;
	/* The cookie context structure should not be held within the cookies
	 * module because of better access. */
	struct kr_cookie_ctx cookie_ctx;
	kr_cookie_lru_t *cache_cookie;
	int32_t tls_padding; /**< See net.tls_padding in ../daemon/README.rst -- -1 is "true" (default policy), 0 is "false" (no padding) */
	knot_mm_t *pool;
};

/** Pointer to the singleton resolver context. NULL if not initialized */
KR_EXPORT extern struct kr_context *the_resolver;

/** Initializes the resolver. */
KR_EXPORT
int kr_resolver_init(module_array_t *modules, knot_mm_t *pool);

/** Cleans up the resolver. */
KR_EXPORT
void kr_resolver_deinit(void);

/* Kept outside, because kres-gen.lua can't handle this depth
 * (and lines here were too long anyway). */
struct kr_request_qsource_flags {
	bool tcp:1; /**< true if the request is not on UDP; only meaningful if (dst_addr). */
	bool tls:1; /**< true if the request is encrypted; only meaningful if (dst_addr). */
	bool http:1; /**< true if the request is on HTTP; only meaningful if (dst_addr). */
	bool xdp:1; /**< true if the request is on AF_XDP; only meaningful if (dst_addr). */
};

/* Extended DNS Errors, RFC 8914 */
struct kr_extended_error {
	int32_t info_code;  /**< May contain -1 (KNOT_EDNS_EDE_NONE); filter before converting to uint16_t. */
	const char *extra_text; /**< Can be NULL.  Allocated on the kr_request::pool or static. */
};


typedef bool (*addr_info_f)(struct sockaddr*);
typedef void (*async_resolution_f)(knot_dname_t*, enum knot_rr_type);
typedef array_t(union kr_sockaddr) kr_sockaddr_array_t;

/**
 * Name resolution request.
 *
 * Keeps information about current query processing between calls to
 * processing APIs, i.e. current resolved query, resolution plan, ...
 * Use this instead of the simple interface if you want to implement
 * multiplexing or custom I/O.
 *
 * @note All data for this request must be allocated from the given pool.
 */
struct kr_request {
	struct kr_context *ctx;
	knot_pkt_t *answer; /**< See kr_request_ensure_answer() */
	struct kr_query *current_query;    /**< Current evaluated query. */
	struct {
		/** Address that originated the request. May be that of a client
		 * behind a proxy, if PROXYv2 is used. Otherwise, it will be
		 * the same as `comm_addr`. `NULL` for internal origin. */
		const struct sockaddr *addr;
		/** Address that communicated the request. This may be the address
		 * of a proxy. It is the same as `addr` if no proxy is used.
		 * `NULL` for internal origin. */
		const struct sockaddr *comm_addr;
		/** Address that accepted the request. `NULL` for internal origin.
		 * Beware: in case of UDP on wildcard address it will be wildcard;
		 * closely related: issue #173. */
		const struct sockaddr *dst_addr;
		const knot_pkt_t *packet;
		/** Request flags from the point of view of the original client.
		 * This client may be behind a proxy. */
		struct kr_request_qsource_flags flags;
		/** Request flags from the point of view of the client actually
		 * communicating with the resolver. When PROXYv2 protocol is used,
		 * this describes the request from the proxy. When there is no
		 * proxy, this will have exactly the same value as `flags`. */
		struct kr_request_qsource_flags comm_flags;
		size_t size; /**< query packet size */
		int32_t stream_id; /**< HTTP/2 stream ID for DoH requests */
		kr_http_header_array_t headers;  /**< HTTP/2 headers for DoH requests */
	} qsource;
	struct {
		unsigned rtt;                  /**< Current upstream RTT */
		const struct kr_transport *transport;   /**< Current upstream transport */
	} upstream;                        /**< Upstream information, valid only in consume() phase */
	struct kr_qflags options;
	int state;
	ranked_rr_array_t answ_selected;
	ranked_rr_array_t auth_selected;
	ranked_rr_array_t add_selected;
	bool answ_validated; /**< internal to validator; beware of caching, etc. */
	bool auth_validated; /**< see answ_validated ^^ ; TODO */

	/** Overall rank for the request.
	 *
	 * Values from kr_rank, currently just KR_RANK_SECURE and _INITIAL.
	 * Only read this in finish phase and after validator, please.
	 * Meaning of _SECURE: all RRs in answer+authority are _SECURE,
	 *   including any negative results implied (NXDOMAIN, NODATA).
	 */
	uint8_t rank;

	struct kr_rplan rplan;
	trace_log_f trace_log; /**< Logging tracepoint */
	trace_callback_f trace_finish; /**< Request finish tracepoint */
	int vars_ref; /**< Reference to per-request variable table. LUA_NOREF if not set. */
	knot_mm_t pool;
	unsigned int uid; /**< for logging purposes only */
	struct {
		addr_info_f is_tls_capable;
		addr_info_f is_tcp_connected;
		addr_info_f is_tcp_waiting;
		kr_sockaddr_array_t forwarding_targets; /**< When forwarding, possible targets are put here */
	} selection_context;
	unsigned int count_no_nsaddr;
	unsigned int count_fail_row;
	alloc_wire_f alloc_wire_cb; /**< CB to allocate answer wire (can be NULL). */
	struct kr_extended_error extended_error;  /**< EDE info; don't modify directly, use kr_request_set_extended_error() */
};

/** Initializer for an array of *_selected. */
#define kr_request_selected(req) { \
	[KNOT_ANSWER] = &(req)->answ_selected, \
	[KNOT_AUTHORITY] = &(req)->auth_selected, \
	[KNOT_ADDITIONAL] = &(req)->add_selected, \
	}

/**
 * Begin name resolution.
 *
 * @note Expects a request to have an initialized mempool.
 *
 * @param request request state with initialized mempool
 * @param ctx     resolution context
 * @return        CONSUME (expecting query)
 */
KR_EXPORT
int kr_resolve_begin(struct kr_request *request, struct kr_context *ctx);

/**
 * Ensure that request->answer->opt_rr is present if query has EDNS.
 *
 * This function should be used after clearing a response packet to ensure its
 * opt_rr is properly set. Returns the opt_rr (for convenience) or NULL.
 */
KR_EXPORT
knot_rrset_t * kr_request_ensure_edns(struct kr_request *request);

/**
 * Ensure that request->answer is usable, and return it (for convenience).
 *
 * It may return NULL, in which case it marks ->state with _FAIL and no answer will be sent.
 * Only use this when it's guaranteed that there will be no delay before sending it.
 * You don't need to call this in places where "resolver knows" that there will be no delay,
 * but even there you need to check if the ->answer is NULL (unless you check for _FAIL anyway).
 */
KR_EXPORT
knot_pkt_t * kr_request_ensure_answer(struct kr_request *request);

/**
 * Consume input packet (may be either first query or answer to query originated from kr_resolve_produce())
 *
 * @note If the I/O fails, provide an empty or NULL packet, this will make iterator recognize nameserver failure.
 *
 * @param  request request state (awaiting input)
 * @param  src     [in] packet source address
 * @param  packet  [in] input packet
 * @return         any state
 */
KR_EXPORT
int kr_resolve_consume(struct kr_request *request, struct kr_transport **transport, knot_pkt_t *packet);

/**
 * Produce either next additional query or finish.
 *
 * If the CONSUME is returned then dst, type and packet will be filled with
 * appropriate values and caller is responsible to send them and receive answer.
 * If it returns any other state, then content of the variables is undefined.
 *
 * @param  request request state (in PRODUCE state)
 * @param  dst     [out] possible address of the next nameserver
 * @param  type    [out] possible used socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param  packet  [out] packet to be filled with additional query
 * @return         any state
 */
KR_EXPORT
int kr_resolve_produce(struct kr_request *request, struct kr_transport **transport, knot_pkt_t *packet);

/**
 * Finalises the outbound query packet with the knowledge of the IP addresses.
 *
 * @note The function must be called before actual sending of the request packet.
 *
 * @param  request request state (in PRODUCE state)
 * @param  src     address from which the query is going to be sent
 * @param  dst     address of the name server
 * @param  type    used socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param  packet  [in,out] query packet to be finalised
 * @return         kr_ok() or error code
 */
KR_EXPORT
int kr_resolve_checkout(struct kr_request *request, const struct sockaddr *src,
                        struct kr_transport *transport, knot_pkt_t *packet);

/**
 * Finish resolution and commit results if the state is DONE.
 *
 * @note The structures will be deinitialized, but the assigned memory pool is not going to
 *       be destroyed, as it's owned by caller.
 *
 * @param  request request state
 * @param  state   either DONE or FAIL state (to be assigned to request->state)
 * @return         DONE
 */
KR_EXPORT
int kr_resolve_finish(struct kr_request *request, int state);

/**
 * Return resolution plan.
 * @param  request request state
 * @return         pointer to rplan
 */
KR_EXPORT KR_PURE
struct kr_rplan *kr_resolve_plan(struct kr_request *request);

/**
 * Return memory pool associated with request.
 * @param  request request state
 * @return         mempool
 */
KR_EXPORT KR_PURE
knot_mm_t *kr_resolve_pool(struct kr_request *request);

/**
 * Set the extended DNS error for request.
 *
 * The error is set only if it has a higher or the same priority as the one
 * already assigned.  The provided extra_text may be NULL, or a string that is
 * allocated either statically, or on the request's mempool. To clear any
 * error, call it with KNOT_EDNS_EDE_NONE and NULL as extra_text.
 *
 * To facilitate debugging, we include a unique base32 identifier at the start
 * of the extra_text field for every call of this function. To generate such an
 * identifier, you can use the command:
 * $ base32 /dev/random | head -c 4
 *
 * @param  request     request state
 * @param  info_code   extended DNS error code
 * @param  extra_text  optional string with additional information
 * @return             info_code that is set after the call
 */
KR_EXPORT
int kr_request_set_extended_error(struct kr_request *request, int info_code, const char *extra_text);

static inline void kr_query_inform_timeout(struct kr_request *req, const struct kr_query *qry)
{
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_NREACH_AUTH, "RRPF");

	unsigned ind = 0;
	for (const struct kr_query *q = qry; q; q = q->parent)
		ind += 2;
	const uint32_t qid = qry ? qry->uid : 0;

	kr_log_req(req, qid, ind, WORKER, "internal timeout for resolving the request has expired\n");
}
