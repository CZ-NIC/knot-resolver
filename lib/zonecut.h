/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/cache/api.h"
#include "lib/defines.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"


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
	trie_t *nsset;        /**< Map of nameserver => address_set (pack_t). */
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
 * Move a zonecut, transferring ownership of any pointed-to memory.
 * @param to the target - it gets deinit-ed
 * @param from the source - not modified, but shouldn't be used afterward
 */
KR_EXPORT
void kr_zonecut_move(struct kr_zonecut *to, const struct kr_zonecut *from);

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
 * @return 0 or an error code; If it fails with kr_error(ENOMEM),
 * it may be in a half-filled state, but it's safe to deinit...
 * @note addresses for names in `src` get replaced and others are left as they were.
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
 * @param data   typically knot_rdata_t::data
 * @param len    typically knot_rdata_t::len
 * @return 0 or error code
 */
KR_EXPORT
int kr_zonecut_add(struct kr_zonecut *cut, const knot_dname_t *ns, const void *data, int len);

/**
 * Delete nameserver/address pair from the zone cut.
 * @param  cut
 * @param  ns    name server name
 * @param  data  typically knot_rdata_t::data
 * @param  len   typically knot_rdata_t::len
 * @return       0 or error code
 */
KR_EXPORT
int kr_zonecut_del(struct kr_zonecut *cut, const knot_dname_t *ns, const void *data, int len);

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
/**
 * Check if any address is present in the zone cut.
 *
 * @param cut zone cut to check
 * @return true/false
 */
KR_EXPORT
bool kr_zonecut_is_empty(struct kr_zonecut *cut);

