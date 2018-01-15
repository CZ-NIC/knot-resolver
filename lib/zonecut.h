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

#include "lib/generic/map.h"
#include "lib/generic/pack.h"
#include "lib/defines.h"
#include "lib/cache.h"

struct kr_rplan;
struct kr_context;

/**
 * Current zone cut representation.
*/
struct kr_zonecut {
	knot_dname_t *name; /**< Zone cut name. */
	knot_rrset_t* key;  /**< Zone cut DNSKEY. */
	knot_rrset_t* trust_anchor; /**< Current trust anchor. */
	struct kr_zonecut *parent; /**< Parent zone cut. */
	map_t nsset;        /**< Map of nameserver => address_set. */
	knot_mm_t *pool;     /**< Memory pool. */
};

/**
 * Populate root zone cut with SBELT.
 * @param cut zone cut
 * @param name
 * @param pool
 * @return 0 or error code
 */
KR_EXPORT
int kr_zonecut_init(struct kr_zonecut *cut, const knot_dname_t *name, knot_mm_t *pool);

/**
 * Clear the structure and free the address set.
 * @param cut zone cut
 */
KR_EXPORT
void kr_zonecut_deinit(struct kr_zonecut *cut);

/**
 * Reset zone cut to given name and clear address list.
 * @note This clears the address list even if the name doesn't change. TA and DNSKEY don't change.
 * @param cut  zone cut to be set
 * @param name new zone cut name
 */
KR_EXPORT
void kr_zonecut_set(struct kr_zonecut *cut, const knot_dname_t *name);

/** 
 * Copy zone cut, including all data. Does not copy keys and trust anchor.
 * @param dst destination zone cut
 * @param src source zone cut
 * @return 0 or an error code
 */
KR_EXPORT
int kr_zonecut_copy(struct kr_zonecut *dst, const struct kr_zonecut *src);

/**
 * Copy zone trust anchor and keys.
 * @param dst destination zone cut
 * @param src source zone cut
 * @return 0 or an error code
 */
KR_EXPORT
int kr_zonecut_copy_trust(struct kr_zonecut *dst, const struct kr_zonecut *src);

/**
 * Add address record to the zone cut.
 *
 * The record will be merged with existing data,
 * it may be either A/AAAA type.
 *
 * @param cut    zone cut to be populated
 * @param ns     nameserver name
 * @param rdata  nameserver address (as rdata)
 * @return 0 or error code
 */
KR_EXPORT
int kr_zonecut_add(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata);

/**
 * Delete nameserver/address pair from the zone cut.
 * @param  cut
 * @param  ns    name server name
 * @param  rdata name server address
 * @return       0 or error code
 */
KR_EXPORT
int kr_zonecut_del(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata);

/**
 * Delete all addresses associated with the given name.
 * @param  cut
 * @param  ns    name server name
 * @return       0 or error code
 */
KR_EXPORT
int kr_zonecut_del_all(struct kr_zonecut *cut, const knot_dname_t *ns);

/**
 * Find nameserver address list in the zone cut.
 *
 * @note This can be used for membership test, a non-null pack is returned
 *       if the nameserver name exists.
 * 
 * @param  cut
 * @param  ns    name server name
 * @return       pack of addresses or NULL
 */
KR_EXPORT KR_PURE
pack_t *kr_zonecut_find(struct kr_zonecut *cut, const knot_dname_t *ns);

/**
 * Populate zone cut with a root zone using SBELT :rfc:`1034`
 *
 * @param ctx resolution context (to fetch root hints)
 * @param cut zone cut to be populated
 * @return 0 or error code
 */
KR_EXPORT
int kr_zonecut_set_sbelt(struct kr_context *ctx, struct kr_zonecut *cut);

/**
 * Populate zone cut address set from cache.
 *
 * @param ctx       resolution context (to fetch data from LRU caches)
 * @param cut       zone cut to be populated
 * @param name      QNAME to start finding zone cut for
 * @param qry       query for timestamp and stale-serving decisions
 * @param secured   set to true if want secured zone cut, will return false if it is provably insecure
 * @return 0 or error code (ENOENT if it doesn't find anything)
 */
KR_EXPORT
int kr_zonecut_find_cached(struct kr_context *ctx, struct kr_zonecut *cut,
			   const knot_dname_t *name, const struct kr_query *qry,
			   bool * restrict secured);
