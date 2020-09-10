/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <sys/time.h>
#include <libknot/dname.h>
#include <libknot/codes.h>

#include "lib/selection.h"
#include "lib/cache/api.h"
#include "lib/zonecut.h"

/** Query flags */
struct kr_qflags {
	bool NO_MINIMIZE : 1;    /**< Don't minimize QNAME. */
	bool NO_THROTTLE : 1;    /**< No query/slow NS throttling. */
	bool NO_IPV6 : 1;        /**< Disable IPv6 */
	bool NO_IPV4 : 1;        /**< Disable IPv4 */
	bool TCP : 1;            /**< Use TCP for this query. */
	bool RESOLVED : 1;       /**< Query is resolved.  Note that kr_query gets
				  *   RESOLVED before following a CNAME chain; see .CNAME. */
	bool AWAIT_IPV4 : 1;     /**< Query is waiting for A address. */
	bool AWAIT_IPV6 : 1;     /**< Query is waiting for AAAA address. */
	bool AWAIT_CUT : 1;      /**< Query is waiting for zone cut lookup */
	bool SAFEMODE : 1;       /**< Don't use fancy stuff (EDNS, 0x20, ...) */
	bool CACHED : 1;         /**< Query response is cached. */
	bool NO_CACHE : 1;       /**< No cache for lookup; exception: finding NSs and subqueries. */
	bool EXPIRING : 1;       /**< Query response is cached, but expiring. */
	bool ALLOW_LOCAL : 1;    /**< Allow queries to local or private address ranges. */
	bool DNSSEC_WANT : 1;    /**< Want DNSSEC secured answer; exception: +cd,
				  * i.e. knot_wire_get_cd(request->qsource.packet->wire) */
	bool DNSSEC_BOGUS : 1;   /**< Query response is DNSSEC bogus. */
	bool DNSSEC_INSECURE : 1;/**< Query response is DNSSEC insecure. */
	bool DNSSEC_CD : 1;      /**< Instruction to set CD bit in request. */
	bool STUB : 1;           /**< Stub resolution, accept received answer as solved. */
	bool ALWAYS_CUT : 1;     /**< Always recover zone cut (even if cached). */
	bool DNSSEC_WEXPAND : 1; /**< Query response has wildcard expansion. */
	bool PERMISSIVE : 1;     /**< Permissive resolver mode. */
	bool STRICT : 1;         /**< Strict resolver mode. */
	bool BADCOOKIE_AGAIN : 1;/**< Query again because bad cookie returned. */
	bool CNAME : 1;          /**< Query response contains CNAME in answer section. */
	bool REORDER_RR : 1;     /**< Reorder cached RRs. */
	bool TRACE : 1;          /**< Also log answers if --verbose. */
	bool NO_0X20 : 1;        /**< Disable query case randomization . */
	bool DNSSEC_NODS : 1;    /**< DS non-existance is proven */
	bool DNSSEC_OPTOUT : 1;  /**< Closest encloser proof has optout */
	bool NONAUTH : 1;        /**< Non-authoritative in-bailiwick records are enough.
				  * TODO: utilize this also outside cache. */
	bool FORWARD : 1;        /**< Forward all queries to upstream; validate answers. */
	bool DNS64_MARK : 1;     /**< Internal mark for dns64 module. */
	bool CACHE_TRIED : 1;    /**< Internal to cache module. */
	bool NO_NS_FOUND : 1;    /**< No valid NS found during last PRODUCE stage. */
	bool PKT_IS_SANE : 1;    /**< Set by iterator in consume phase to indicate whether
				  * some basic aspects of the packet are OK, e.g. QNAME. */
	bool IS_ASYNC_NS : 1;    /**< Request is a async NS resolution for server selection */
};

/** Combine flags together.  This means set union for simple flags. */
KR_EXPORT
void kr_qflags_set(struct kr_qflags *fl1, struct kr_qflags fl2);

/** Remove flags.  This means set-theoretic difference. */
KR_EXPORT
void kr_qflags_clear(struct kr_qflags *fl1, struct kr_qflags fl2);

/** Callback for serve-stale decisions.
 * @param ttl the expired TTL (i.e. it's < 0)
 * @return the adjusted TTL (typically 1) or < 0.
 */
typedef int32_t (*kr_stale_cb)(int32_t ttl, const knot_dname_t *owner, uint16_t type,
				const struct kr_query *qry);

/**
 * Single query representation.
 */
struct kr_query {
	struct kr_query *parent;
	knot_dname_t *sname; /**< The name to resolve - lower-cased, uncompressed. */
	uint16_t stype;
	uint16_t sclass;
	uint16_t id;
	uint16_t reorder; /**< Seed to reorder (cached) RRs in answer or zero. */
	struct kr_qflags flags;
	struct kr_qflags forward_flags;
	uint32_t secret;
	uint32_t uid; /**< Query iteration number, unique within the kr_rplan. */
	uint64_t creation_time_mono; /* The time of query's creation (milliseconds).
				 * Or time of creation of an oldest
				 * ancestor if it is a subquery. */
	uint64_t timestamp_mono; /**< Time of query created or time of
	                           * query to upstream resolver (milliseconds). */
	struct timeval timestamp; /**< Real time for TTL+DNSSEC checks (.tv_sec only). */
	struct kr_zonecut zone_cut;
	struct kr_layer_pickle *deferred;

	/** Current xNAME depth, set by iterator.  0 = uninitialized, 1 = no CNAME, ...
	 * See also KR_CNAME_CHAIN_LIMIT. */
	int8_t cname_depth;
	/** Pointer to the query that originated this one because of following a CNAME (or NULL). */
	struct kr_query *cname_parent;
	struct kr_request *request; /**< Parent resolution request. */
	kr_stale_cb stale_cb; /**< See the type */
	struct kr_server_selection server_selection;
};

/** @cond internal Array of queries. */
typedef array_t(struct kr_query *) kr_qarray_t;
/* @endcond */

/**
 * Query resolution plan structure.
 *
 * The structure most importantly holds the original query, answer and the
 * list of pending queries required to resolve the original query.
 * It also keeps a notion of current zone cut.
 */
struct kr_rplan {
	kr_qarray_t pending;        /**< List of pending queries.
					Beware: order is significant ATM,
					as the last is the next one to solve,
					and they may be inter-dependent. */
	kr_qarray_t resolved;       /**< List of resolved queries. */
	struct kr_query *initial;   /**< The initial query (also in pending or resolved). */

	struct kr_request *request; /**< Parent resolution request. */
	knot_mm_t *pool;            /**< Temporary memory pool. */
	uint32_t next_uid;          /**< Next value for kr_query::uid (incremental). */
};

/**
 * Initialize resolution plan (empty).
 * @param rplan plan instance
 * @param request resolution request
 * @param pool ephemeral memory pool for whole resolution
 */
KR_EXPORT
int kr_rplan_init(struct kr_rplan *rplan, struct kr_request *request, knot_mm_t *pool);

/**
 * Deinitialize resolution plan, aborting any uncommited transactions.
 * @param rplan plan instance
 */
KR_EXPORT
void kr_rplan_deinit(struct kr_rplan *rplan);

/**
 * Return true if the resolution plan is empty (i.e. finished or initialized)
 * @param rplan plan instance
 * @return true or false
 */
KR_EXPORT KR_PURE
bool kr_rplan_empty(struct kr_rplan *rplan);

/**
 * Push empty query to the top of the resolution plan.
 * @note This query serves as a cookie query only.
 * @param rplan plan instance
 * @param parent query parent (or NULL)
 * @return query instance or NULL
 */
KR_EXPORT
struct kr_query *kr_rplan_push_empty(struct kr_rplan *rplan,
                                     struct kr_query *parent);

/**
 * Push a query to the top of the resolution plan.
 * @note This means that this query takes precedence before all pending queries.
 * @param rplan plan instance
 * @param parent query parent (or NULL)
 * @param name resolved name
 * @param cls  resolved class
 * @param type resolved type
 * @return query instance or NULL
 */
KR_EXPORT
struct kr_query *kr_rplan_push(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type);

/**
 * Pop existing query from the resolution plan.
 * @note Popped queries are not discarded, but moved to the resolved list.
 * @param rplan plan instance
 * @param qry resolved query
 * @return 0 or an error
 */
KR_EXPORT
int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry);

/**
 * Return true if resolution chain satisfies given query.
 */
KR_EXPORT KR_PURE
bool kr_rplan_satisfies(struct kr_query *closure, const knot_dname_t *name, uint16_t cls, uint16_t type);

/** Return last resolved query. */
KR_EXPORT KR_PURE
struct kr_query *kr_rplan_resolved(struct kr_rplan *rplan);

/**
  * Return last query (either currently being solved or last resolved).
  * This is necessary to retrieve the last query in case of resolution failures (e.g. time limit reached).
  */
KR_EXPORT KR_PURE
struct kr_query *kr_rplan_last(struct kr_rplan *rplan);


/**
 * Check if a given query already resolved.
 * @param rplan plan instance
 * @param parent query parent (or NULL)
 * @param name resolved name
 * @param cls  resolved class
 * @param type resolved type
 * @return query instance or NULL
 */
KR_EXPORT KR_PURE
struct kr_query *kr_rplan_find_resolved(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type);
