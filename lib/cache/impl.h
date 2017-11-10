/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/** @file
 * Header internal for cache implementation(s).
 * Only LMDB works for now.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <libknot/consts.h>
#include <libknot/db/db.h>
#include <libknot/dname.h>

#include "lib/cdb.h"
#include "lib/resolve.h"

/** Cache entry header
 *
 * 'E' entry (exact hit):
 *	- ktype == NS: multiple chained entry_h, based on has_* : 1 flags;
 *		TODO: NSEC3 chain descriptors (iff nsec3_cnt > 0)
 *	- is_packet: uint16_t length, otherwise opaque and handled by ./entry_pkt.c
 *	- otherwise RRset + its RRSIG set (possibly empty).
 * */
struct entry_h {
	uint32_t time;	/**< The time of inception. */
	uint32_t ttl;	/**< TTL at inception moment.  Assuming it fits into int32_t ATM. */
	uint8_t  rank;	/**< See enum kr_rank */

	bool is_packet : 1;	/**< Negative-answer packet for insecure/bogus name. */

	unsigned nsec1_pos : 2;	/**< Only used for NS ktype. */
	unsigned nsec3_cnt : 2;	/**< Only used for NS ktype. */
	bool has_ns : 1;	/**< Only used for NS ktype. */
	bool has_cname : 1;	/**< Only used for NS ktype. */
	bool has_dname : 1;	/**< Only used for NS ktype. */
	/* ENTRY_H_FLAGS */

	uint8_t data[];
};


/** Check basic consistency of entry_h, not looking into ->data.
 * (for is_packet the length of data is checked)
 * \note only exact hits and NSEC1 are really considered ATM.
 */
struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t ktype);


// TODO
#define KR_CACHE_KEY_MAXLEN (KNOT_DNAME_MAXLEN + 100)

struct key {
	const knot_dname_t *zname; /**< current zone name (points within qry->sname) */
	uint8_t zlf_len; /**< length of current zone's lookup format */

	uint16_t type; /**< corresponding type */
	uint8_t buf[KR_CACHE_KEY_MAXLEN];
};

static inline size_t key_nwz_off(const struct key *k)
{
	/* CACHE_KEY_DEF: zone name lf + 0 '1' + name within zone */
	return k->zlf_len + 2;
}

/** Finish constructing string key for for exact search.
 * It's assumed that kr_dname_lf(k->buf, owner, NULL) had been ran.
 */
knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type);


/* entry_h chaining; implementation in ./entry_list.c */

/** There may be multiple entries within, so rewind `val` to the one we want.
 *
 * ATM there are multiple types only for the NS ktype.
 * \return error code
 */
int entry_h_seek(knot_db_val_t *val, uint16_t type);

/** Prepare space to insert an entry.
 *
 * Some checks are performed (rank, TTL), the current entry in cache is copied
 * with a hole ready for the new entry (old one of the same type is cut out).
 *
 * \param val_new_entry The only changing parameter; ->len is read, ->data written.
 * Beware: the entry_h in *val_new_entry->data is zeroed, and in some cases it has
 * some flags set - and in those cases you can't just overwrite those flags.
 * All flags except is_packet are sensitive in this way.
 */
int entry_h_splice(
	knot_db_val_t *val_new_entry, uint8_t rank,
	const knot_db_val_t key, const uint16_t ktype, const uint16_t type,
	const knot_dname_t *owner/*log only*/,
	const struct kr_query *qry, struct kr_cache *cache);


/* Packet caching; implementation in ./entry_pkt.c */

/** Stash the packet into cache (if suitable, etc.) */
void stash_pkt(const knot_pkt_t *pkt, const struct kr_query *qry,
		const struct kr_request *req);

/** Try answering from packet cache, given an entry_h.
 *
 * This assumes the TTL is OK and entry_h_consistent, but it may still return error.
 * On success it handles all the rest, incl. qry->flags.
 */
int answer_from_pkt(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);


/** Don't go under this TTL, to avoid bursts of queries. */
static const uint32_t DEFAULT_MINTTL = 5;

/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static inline bool is_expiring(uint32_t orig_ttl, uint32_t new_ttl)
{
	int64_t nttl = new_ttl; /* avoid potential over/under-flow */
	return 100 * (nttl - 5) < orig_ttl;
}

int32_t get_new_ttl(const struct entry_h *entry, uint32_t current_time);


/* RRset (de)materialization; implementation in ./entry_rr.c */

/** Compute size of dematerialized rdataset.  NULL is accepted as empty set. */
static inline int rdataset_dematerialize_size(const knot_rdataset_t *rds)
{
	return 1/*sizeof(rr_count)*/ + (rds
		? knot_rdataset_size(rds) - 4 * rds->rr_count /*TTLs*/
		: 0);
}

/** Dematerialize a rdataset. */
int rdataset_dematerialize(const knot_rdataset_t *rds, void * restrict data);

/** Partially constructed answer when gathering RRsets from cache. */
struct answer {
	int rcode;	/**< PKT_NODATA, etc. ?? */
	uint8_t nsec_v;	/**< 1 or 3 */
	knot_mm_t *mm;	/**< Allocator for rrsets */
	struct answer_rrset {
		ranked_rr_array_entry_t set;	/**< set+rank for the main data */
		knot_rdataset_t sig_rds;	/**< RRSIG data, if any */
	} rrsets[1+1+3]; /**< see AR_ANSWER and friends; only required records are filled */
};
enum {
	AR_ANSWER = 0,	/**< Positive answer record.  It might be wildcard-expanded. */
	AR_SOA, 	/**< SOA record. */
	AR_NSEC,	/**< NSEC* covering the SNAME. */
	AR_WILD,	/**< NSEC* covering or matching the source of synthesis. */
	AR_CPE, 	/**< NSEC3 matching the closest provable encloser. */
};

/** Materialize RRset + RRSIGs into ans->rrsets[id].
 * LATER(optim.): it's slightly wasteful that we allocate knot_rrset_t for the packet
 */
int entry2answer(struct answer *ans, int id,
		const struct entry_h *eh, const void *eh_bound,
		const knot_dname_t *owner, uint16_t type, uint32_t new_ttl);


/* Preparing knot_pkt_t for cache answer from RRs; implementation in ./knot_pkt.c */

/** Prepare answer packet to be filled by RRs (without RR data in wire). */
int pkt_renew(knot_pkt_t *pkt, const knot_dname_t *name, uint16_t type);

/** Append RRset + its RRSIGs into the current section (*shallow* copy), with given rank.
 * \note it works with empty set as well (skipped)
 * \note pkt->wire is not updated in any way
 * \note KNOT_CLASS_IN is assumed
 */
int pkt_append(knot_pkt_t *pkt, const struct answer_rrset *rrset, uint8_t rank);


#define VERBOSE_MSG(qry, fmt...) QRVERBOSE((qry), "cach",  fmt)



/** Shorthand for operations on cache backend */
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, ## __VA_ARGS__)

