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

#include <libknot/consts.h>
#include <libknot/rrset.h>
#include "lib/cdb.h"
#include "lib/defines.h"
#include "contrib/ucw/config.h" /*uint*/

/** When knot_pkt is passed from cache without ->wire, this is the ->size. */
static const size_t PKT_SIZE_NOWIRE = -1;

// TODO
#define KR_CACHE_KEY_MAXLEN (KNOT_DNAME_MAXLEN + 100)

/** Cache entry tag */
enum kr_cache_tag {
	KR_CACHE_RR   = 'R',
	KR_CACHE_PKT  = 'P',
	KR_CACHE_SIG  = 'G',
	KR_CACHE_USER = 0x80
};

/** Cache entry flags */
enum kr_cache_flag {
	KR_CACHE_FLAG_NONE	  = 0,
	KR_CACHE_FLAG_WCARD_PROOF = 1, /* Entry contains either packet with wildcard
	                                * answer either record for which wildcard
	                                * expansion proof is needed */
	KR_CACHE_FLAG_OPTOUT	  = 2, /* Entry contains secured packet containing a
					* closest  encloser proof in which the NSEC3 RR
					* that covers the "next closer" name
					* has the Opt-Out bit set
					*/
	KR_CACHE_FLAG_NODS	  = 4, /* Entry contains NS rrset
					* for which DS nonexistence is proven.
					*/
};


/**
 * Serialized form of the RRSet with inception timestamp and maximum TTL.
 */
struct kr_cache_entry
{
	uint32_t timestamp;
	uint32_t ttl;
	uint16_t count;
	uint8_t  rank;
	uint8_t  flags;
	uint8_t  data[];
};

/**
 * Cache structure, keeps API, instance and metadata.
 */
struct kr_cache
{
	knot_db_t *db;		      /**< Storage instance */
	const struct kr_cdb_api *api; /**< Storage engine */
	struct {
		uint32_t hit;         /**< Number of cache hits */
		uint32_t miss;        /**< Number of cache misses */
		uint32_t insert;      /**< Number of insertions */
		uint32_t delete;      /**< Number of deletions */
	} stats;

	uint32_t ttl_min, ttl_max; /**< Maximum TTL of inserted entries */
};



#include "lib/module.h"
int cache_lmdb_peek(kr_layer_t *ctx, knot_pkt_t *pkt);
int cache_lmdb_stash(kr_layer_t *ctx, knot_pkt_t *pkt);

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
 * Close persistent cache.
 * @note This doesn't clear the data, just closes the connection to the database.
 * @param cache structure
 */
KR_EXPORT
void kr_cache_close(struct kr_cache *cache);

/** Run after a row of operations to release transaction/lock if needed. */
KR_EXPORT
int kr_cache_sync(struct kr_cache *cache);

/**
 * Return true if cache is open and enabled.
 */
static inline bool kr_cache_is_open(struct kr_cache *cache)
{
	return cache->db != NULL;
}

#if 0
/**
 * Peek the cache for asset (name, type, tag)
 * @note The 'drift' is the time passed between the inception time and now (in seconds).
 * @param cache cache structure
 * @param tag  asset tag
 * @param name asset name
 * @param type asset type
 * @param entry cache entry, will be set to valid pointer or NULL
 * @param timestamp current time (will be replaced with drift if successful)
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_peek(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type,
                  struct kr_cache_entry **entry, uint32_t *timestamp);



/**
 * Insert asset into cache, replacing any existing data.
 * @param cache cache structure
 * @param tag  asset tag
 * @param name asset name
 * @param type asset type
 * @param header filled entry header (count, ttl and timestamp)
 * @param data inserted data
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_insert(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type,
                    struct kr_cache_entry *header, knot_db_val_t data);

/**
 * Remove asset from cache.
 * @param cache cache structure
 * @param tag asset tag
 * @param name asset name
 * @param type record type
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_remove(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type);

#endif
/**
 * Clear all items from the cache.
 * @param cache cache structure
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_clear(struct kr_cache *cache);


/* ** This interface is temporary. ** */

struct kr_cache_p {
	uint32_t time;	/**< The time of inception. */
	uint32_t ttl;	/**< TTL at inception moment.  Assuming it fits into int32_t ATM. */
	uint8_t  rank;	/**< See enum kr_rank */
	struct {
		uint8_t *data, *data_bound;
	};
};
KR_EXPORT
int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek);
KR_EXPORT
int32_t kr_cache_ttl(const struct kr_cache_p *peek, uint32_t current_time);
/*TODO: reorder*/
KR_EXPORT
int kr_cache_materialize(knot_rdataset_t *dst, const struct kr_cache_p *ref,
			 uint32_t new_ttl, knot_mm_t *pool);


#if 0

/**
 * Prefix scan on cached items.
 * @param cache cache structure
 * @param tag asset tag
 * @param name asset prefix key
 * @param vals array of values to store the result
 * @param valcnt maximum number of retrieved keys
 * @return number of retrieved keys or an error
 */
KR_EXPORT
int kr_cache_match(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, knot_db_val_t *vals, int valcnt);

/**
 * Peek the cache for given key and retrieve it's rank.
 * @param cache cache structure
 * @param tag asset tag
 * @param name asset name
 * @param type record type
 * @param timestamp current time
 * @return rank (0 or positive), or an error (negative number)
 */
KR_EXPORT
int kr_cache_peek_rank(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type, uint32_t timestamp);

/**
 * Peek the cache for given RRSet (name, type)
 * @note The 'drift' is the time passed between the cache time of the RRSet and now (in seconds).
 * @param cache cache structure
 * @param rr query RRSet (its rdataset may be changed depending on the result)
 * @param rank entry rank will be stored in this variable
 * @param flags entry flags
 * @param timestamp current time (will be replaced with drift if successful)
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_peek_rr(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank, uint8_t *flags, uint32_t *timestamp);

/**
 * Clone read-only RRSet and adjust TTLs.
 * @param dst destination for materialized RRSet
 * @param src read-only RRSet (its rdataset may be changed depending on the result)
 * @param drift time passed between cache time and now
 * @param reorder (pseudo)-random seed to reorder the data or zero
 * @param mm memory context
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_materialize(knot_rrset_t *dst, const knot_rrset_t *src, uint32_t drift,
		uint reorder, knot_mm_t *mm);

/**
 * Insert RRSet into cache, replacing any existing data.
 * @param cache cache structure
 * @param rr inserted RRSet
 * @param rank rank of the data
 * @param flags additional flags for the data
 * @param timestamp current time
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_insert_rr(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp);

/**
 * Peek the cache for the given RRset signature (name, type)
 * @note The RRset type must not be RRSIG but instead it must equal the type covered field of the sought RRSIG.
 * @param cache cache structure
 * @param rr query RRSET (its rdataset and type may be changed depending on the result)
 * @param rank entry rank will be stored in this variable
 * @param flags entry additional flags
 * @param timestamp current time (will be replaced with drift if successful)
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_peek_rrsig(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank, uint8_t *flags, uint32_t *timestamp);

/**
 * Insert the selected RRSIG RRSet of the selected type covered into cache, replacing any existing data.
 * @note The RRSet must contain RRSIGS with only the specified type covered.
 * @param cache cache structure
 * @param rr inserted RRSIG RRSet
 * @param rank rank of the data
 * @param flags additional flags for the data
 * @param timestamp current time
 * @return 0 or an errcode
 */
KR_EXPORT
int kr_cache_insert_rrsig(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp);

#endif
