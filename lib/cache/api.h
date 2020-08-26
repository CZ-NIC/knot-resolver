/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/consts.h>
#include <libknot/rrset.h>
#include <sys/time.h>
#include "lib/cache/cdb_api.h"
#include "lib/defines.h"
#include "contrib/ucw/config.h" /*uint*/

/** When knot_pkt is passed from cache without ->wire, this is the ->size. */
static const size_t PKT_SIZE_NOWIRE = -1;


#include "lib/module.h"
/* Prototypes for the 'cache' module implementation. */
int cache_peek(kr_layer_t *ctx, knot_pkt_t *pkt);
int cache_stash(kr_layer_t *ctx, knot_pkt_t *pkt);


/**
 * Cache structure, keeps API, instance and metadata.
 */
struct kr_cache
{
	knot_db_t *db;		      /**< Storage instance */
	const struct kr_cdb_api *api; /**< Storage engine */
	struct kr_cdb_stats stats;
	uint32_t ttl_min, ttl_max; /**< TTL limits */

	/* A pair of stamps for detection of real-time shifts during runtime. */
	struct timeval checkpoint_walltime; /**< Wall time on the last check-point. */
	uint64_t checkpoint_monotime; /**< Monotonic milliseconds on the last check-point. */

	uv_timer_t *health_timer; /**< Timer used for kr_cache_check_health() */
};

/**
 * Open/create cache with provided storage options.
 * @param cache cache structure to be initialized
 * @param api   storage engine API
 * @param opts  storage-specific options (may be NULL for default)
 * @param mm    memory context.
 * @return 0 or an error code
 */
KR_EXPORT
int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm);

/**
 * Path to cache file to remove on critical out-of-space error. (do NOT modify it)
 */
KR_EXPORT extern
const char *kr_cache_emergency_file_to_remove;

/**
 * Close persistent cache.
 * @note This doesn't clear the data, just closes the connection to the database.
 * @param cache structure
 */
KR_EXPORT
void kr_cache_close(struct kr_cache *cache);

/** Run after a row of operations to release transaction/lock if needed. */
KR_EXPORT
int kr_cache_commit(struct kr_cache *cache);

/**
 * Return true if cache is open and enabled.
 */
static inline bool kr_cache_is_open(struct kr_cache *cache)
{
	return cache->db != NULL;
}

/** (Re)set the time pair to the current values. */
static inline void kr_cache_make_checkpoint(struct kr_cache *cache)
{
	cache->checkpoint_monotime = kr_now();
	gettimeofday(&cache->checkpoint_walltime, NULL);
}

/**
 * Insert RRSet into cache, replacing any existing data.
 * @param cache cache structure
 * @param rr inserted RRSet
 * @param rrsig RRSIG for inserted RRSet (optional)
 * @param rank rank of the data
 * @param timestamp current time
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_insert_rr(struct kr_cache *cache, const knot_rrset_t *rr, const knot_rrset_t *rrsig, uint8_t rank, uint32_t timestamp);

/**
 * Clear all items from the cache.
 * @param cache cache structure
 * @return if nonzero is returned, there's a big problem - you probably want to abort(),
 * 	perhaps except for kr_error(EAGAIN) which probably indicates transient errors.
 */
KR_EXPORT
int kr_cache_clear(struct kr_cache *cache);


/* ** This interface is temporary. ** */

struct kr_cache_p {
	uint32_t time;	/**< The time of inception. */
	uint32_t ttl;	/**< TTL at inception moment.  Assuming it fits into int32_t ATM. */
	uint8_t  rank;	/**< See enum kr_rank */
	struct {
		/* internal: pointer to eh struct */
		void *raw_data, *raw_bound;
	};
};
KR_EXPORT
int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek);
/* Parameters (qry, name, type) are used for timestamp and stale-serving decisions. */
KR_EXPORT
int32_t kr_cache_ttl(const struct kr_cache_p *peek, const struct kr_query *qry,
		     const knot_dname_t *name, uint16_t type);

KR_EXPORT
int kr_cache_materialize(knot_rdataset_t *dst, const struct kr_cache_p *ref,
			 knot_mm_t *pool);


/**
 * Remove an entry from cache.
 * @param cache cache structure
 * @param name dname
 * @param type rr type
 * @return number of deleted records, or negative error code
 * @note only "exact hits" are considered ATM, and
 * 	some other information may be removed alongside.
 */
KR_EXPORT
int kr_cache_remove(struct kr_cache *cache, const knot_dname_t *name, uint16_t type);

/**
 * Get keys matching a dname lf prefix
 * @param cache cache structure
 * @param name dname
 * @param exact_name whether to only consider exact name matches
 * @param keyval matched key-value pairs
 * @param maxcount limit on the number of returned key-value pairs
 * @return result count or an errcode
 * @note the cache keys are matched by prefix, i.e. it very much depends
 * 	on their structure; CACHE_KEY_DEF.
 */
KR_EXPORT
int kr_cache_match(struct kr_cache *cache, const knot_dname_t *name,
		   bool exact_name, knot_db_val_t keyval[][2], int maxcount);

/**
 * Remove a subtree in cache.  It's like _match but removing them instead of returning.
 * @return number of deleted entries or an errcode
 */
KR_EXPORT
int kr_cache_remove_subtree(struct kr_cache *cache, const knot_dname_t *name,
			    bool exact_name, int maxcount);

/**
 * Find the closest cached zone apex for a name (in cache).
 * @param is_DS start searching one name higher
 * @return the number of labels to remove from the name, or negative error code
 * @note timestamp is found by a syscall, and stale-serving is not considered
 */
KR_EXPORT
int kr_cache_closest_apex(struct kr_cache *cache, const knot_dname_t *name, bool is_DS,
			  knot_dname_t **apex);

/**
 * Unpack dname and type from db key
 * @param key db key representation
 * @param buf output buffer of domain name in dname format
 * @param type output for type
 * @return length of dname or an errcode
 * @note only "exact hits" are considered ATM, moreover xNAME records
 * 	are "hidden" as NS. (see comments in struct entry_h)
 */
KR_EXPORT
int kr_unpack_cache_key(knot_db_val_t key, knot_dname_t *buf, uint16_t *type);

/** Periodic kr_cdb_api::check_health().
 * @param interval in milliseconds.  0 for one-time check, -1 to stop the checks.
 * @return see check_health() for one-time check; otherwise normal kr_error() code. */
KR_EXPORT
int kr_cache_check_health(struct kr_cache *cache, int interval);

