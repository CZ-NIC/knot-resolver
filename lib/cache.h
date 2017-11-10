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
		/* internal: pointer to eh struct */
		void *raw_data, *raw_bound;
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


