/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Header internal for cache implementation(s).
 * Only LMDB works for now.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <libdnssec/error.h>
#include <libdnssec/nsec.h>
#include <libknot/consts.h>
#include <libknot/db/db.h>
#include <libknot/dname.h>

#include "contrib/cleanup.h"
#include "contrib/murmurhash3/murmurhash3.h" /* hash() for nsec_p_hash() */
#include "lib/cache/cdb_api.h"
#include "lib/resolve.h"

/* Cache entry values - binary layout.
 *
 * It depends on type which is recognizable by the key.
 * Code depending on the contents of the key is marked by CACHE_KEY_DEF.
 *
 * 'E' entry (exact hit):
 *	- ktype == NS: struct entry_apex - multiple types inside (NS and xNAME);
 *	- ktype != NS: struct entry_h
 *	    * is_packet: uint16_t length, the rest is opaque and handled by ./entry_pkt.c
 *	    * otherwise RRset + its RRSIG set (possibly empty).
 * '1' or '3' entry (NSEC or NSEC3)
 *	- struct entry_h, contents is the same as for exact hit
 *	- flags don't make sense there
 */

struct entry_h {
	uint32_t time;	/**< The time of inception. */
	uint32_t ttl;	/**< TTL at inception moment.  Assuming it fits into int32_t ATM. */
	uint8_t  rank : 6;	/**< See enum kr_rank */
	bool is_packet : 1;	/**< Negative-answer packet for insecure/bogus name. */
	bool has_optout : 1;	/**< Only for packets; persisted DNSSEC_OPTOUT. */
	uint8_t _pad;		/**< We need even alignment for data now. */
	uint8_t data[];
/* Well, we don't really need packing or alignment changes,
 * but due to LMDB the whole structure may not be stored at an aligned address,
 * and we need compilers (for non-x86) to know it to avoid SIGBUS (test: UBSAN). */
} __attribute__ ((packed,aligned(1)));
struct entry_apex;

/** Check basic consistency of entry_h for 'E' entries, not looking into ->data.
 * (for is_packet the length of data is checked)
 */
KR_EXPORT
struct entry_h * entry_h_consistent_E(knot_db_val_t data, uint16_t type);

struct entry_apex * entry_apex_consistent(knot_db_val_t val);

/** Consistency check, ATM common for NSEC and NSEC3. */
static inline struct entry_h * entry_h_consistent_NSEC(knot_db_val_t data)
{
	/* ATM it's enough to just extend the checks for exact entries. */
	const struct entry_h *eh = entry_h_consistent_E(data, KNOT_RRTYPE_NSEC);
	bool ok = eh != NULL;
	ok = ok && !eh->is_packet && !eh->has_optout;
	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}

static inline struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t type)
{
	switch (type) {
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		return entry_h_consistent_NSEC(data);
	default:
		return entry_h_consistent_E(data, type);
	}
}

/* nsec_p* - NSEC* chain parameters */

static inline int nsec_p_rdlen(const uint8_t *rdata)
{
	//TODO: do we really need the zero case?
	return rdata ? 5 + rdata[4] : 0; /* rfc5155 4.2 and 3.2. */
}
static const int NSEC_P_MAXLEN = sizeof(uint32_t) + 5 + 255; // TODO: remove??

/** Hash of NSEC3 parameters, used as a tag to separate different chains for same zone. */
typedef uint32_t nsec_p_hash_t;
static inline nsec_p_hash_t nsec_p_mkHash(const uint8_t *nsec_p)
{
	assert(nsec_p && !(KNOT_NSEC3_FLAG_OPT_OUT & nsec_p[1]));
	return hash((const char *)nsec_p, nsec_p_rdlen(nsec_p));
}

/** NSEC* parameters for the chain. */
struct nsec_p {
	const uint8_t *raw; /**< Pointer to raw NSEC3 parameters; NULL for NSEC. */
	nsec_p_hash_t hash; /**< Hash of `raw`, used for cache keys. */
	dnssec_nsec3_params_t libknot; /**< Format for libknot; owns malloced memory! */
};



/** LATER(optim.): this is overshot, but struct key usage should be cheap ATM. */
#define KR_CACHE_KEY_MAXLEN (KNOT_DNAME_MAXLEN + 100) /* CACHE_KEY_DEF */

struct key {
	const knot_dname_t *zname; /**< current zone name (points within qry->sname) */
	uint8_t zlf_len; /**< length of current zone's lookup format */

	/** Corresponding key type; e.g. NS for CNAME.
	 * Note: NSEC type is ambiguous (exact and range key). */
	uint16_t type;
	/** The key data start at buf+1, and buf[0] contains some length.
	 * For details see key_exact* and key_NSEC* functions. */
	uint8_t buf[KR_CACHE_KEY_MAXLEN];
	/* LATER(opt.): ^^ probably change the anchoring, so that kr_dname_lf()
	 * doesn't need to move data after knot_dname_lf(). */
};

static inline size_t key_nwz_off(const struct key *k)
{
	/* CACHE_KEY_DEF: zone name lf + 0 ('1' or '3').
	 * NSEC '1' case continues just with the name within zone. */
	return k->zlf_len + 2;
}
static inline size_t key_nsec3_hash_off(const struct key *k)
{
	/* CACHE_KEY_DEF NSEC3: tag (nsec_p_hash_t) + 20 bytes NSEC3 name hash) */
	return key_nwz_off(k) + sizeof(nsec_p_hash_t);
}
/** Hash is always SHA1; I see no plans to standardize anything else.
 * https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml#dnssec-nsec3-parameters-3
 */
static const int NSEC3_HASH_LEN = 20,
		 NSEC3_HASH_TXT_LEN = 32;

/** Finish constructing string key for for exact search.
 * It's assumed that kr_dname_lf(k->buf, owner, *) had been ran.
 */
knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type);

/** Like key_exact_type_maypkt but with extra checks if used for RRs only. */
static inline knot_db_val_t key_exact_type(struct key *k, uint16_t type)
{
	switch (type) {
	/* Sanity check: forbidden types represented in other way(s). */
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}
	return key_exact_type_maypkt(k, type);
}


/* entry_h chaining; implementation in ./entry_list.c */

enum { ENTRY_APEX_NSECS_CNT = 2 };

/** Header of 'E' entry with ktype == NS.  Inside is private to ./entry_list.c
 *
 * We store xNAME at NS type to lower the number of searches in closest_NS().
 * CNAME is only considered for equal name, of course.
 * We also store NSEC* parameters at NS type.
 */
struct entry_apex {
	/* ENTRY_H_FLAGS */
	bool has_ns : 1;
	bool has_cname : 1;
	bool has_dname : 1;

	uint8_t pad_; /**< Weird: 1 byte + 2 bytes + x bytes; let's do 2+2+x. */
	int8_t nsecs[ENTRY_APEX_NSECS_CNT]; /**< values:  0: none, 1: NSEC, 3: NSEC3 */
	uint8_t data[];
	/* XXX: if not first, stamp of last being the first?
	 * Purpose: save cache operations if rolled the algo/params long ago. */
};

/** Indices for decompressed entry_list_t. */
enum EL {
	EL_NS = ENTRY_APEX_NSECS_CNT,
	EL_CNAME,
	EL_DNAME,
	EL_LENGTH
};
/** Decompressed entry_apex.  It's an array of unparsed entry_h references.
 * Note: arrays are passed "by reference" to functions (in C99). */
typedef knot_db_val_t entry_list_t[EL_LENGTH];

static inline uint16_t EL2RRTYPE(enum EL i)
{
	switch (i) {
	case EL_NS:	return KNOT_RRTYPE_NS;
	case EL_CNAME:	return KNOT_RRTYPE_CNAME;
	case EL_DNAME:	return KNOT_RRTYPE_DNAME;
	default:	assert(false);  return 0;
	}
}

/** There may be multiple entries within, so rewind `val` to the one we want.
 *
 * ATM there are multiple types only for the NS ktype - it also accommodates xNAMEs.
 * \note `val->len` represents the bound of the whole list, not of a single entry.
 * \note in case of ENOENT, `val` is still rewound to the beginning of the next entry.
 * \return error code
 * TODO: maybe get rid of this API?
 */
int entry_h_seek(knot_db_val_t *val, uint16_t type);

/** Prepare space to insert an entry.
 *
 * Some checks are performed (rank, TTL), the current entry in cache is copied
 * with a hole ready for the new entry (old one of the same type is cut out).
 *
 * \param val_new_entry The only changing parameter; ->len is read, ->data written.
 * \return error code
 */
int entry_h_splice(
	knot_db_val_t *val_new_entry, uint8_t rank,
	const knot_db_val_t key, const uint16_t ktype, const uint16_t type,
	const knot_dname_t *owner/*log only*/,
	const struct kr_query *qry, struct kr_cache *cache, uint32_t timestamp);

/** Parse an entry_apex into individual items.  @return error code. */
KR_EXPORT int entry_list_parse(const knot_db_val_t val, entry_list_t list);

static inline size_t to_even(size_t n)
{
	return n + (n & 1);
}

static inline int entry_list_serial_size(const entry_list_t list)
{
	int size = offsetof(struct entry_apex, data);
	for (int i = 0; i < EL_LENGTH; ++i) {
		size += to_even(list[i].len);
	}
	return size;
}

/** Fill contents of an entry_apex.
 *
 * @note NULL pointers are overwritten - caller may like to fill the space later.
 */
void entry_list_memcpy(struct entry_apex *ea, entry_list_t list);



/* Packet caching; implementation in ./entry_pkt.c */

/** Stash the packet into cache (if suitable, etc.)
 * \param needs_pkt we need the packet due to not stashing some RRs;
 * 		see stash_rrset() for details
 * It assumes check_dname_for_lf(). */
void stash_pkt(const knot_pkt_t *pkt, const struct kr_query *qry,
		const struct kr_request *req, bool needs_pkt);

/** Try answering from packet cache, given an entry_h.
 *
 * This assumes the TTL is OK and entry_h_consistent, but it may still return error.
 * On success it handles all the rest, incl. qry->flags.
 */
int answer_from_pkt(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);


/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static inline bool is_expiring(uint32_t orig_ttl, uint32_t new_ttl)
{
	int64_t nttl = new_ttl; /* avoid potential over/under-flow */
	return 100 * (nttl - 5) < orig_ttl;
}

/** Returns signed result so you can inspect how much stale the RR is.
 *
 * @param owner name for stale-serving decisions.  You may pass NULL to disable stale.
 * @note: NSEC* uses zone name ATM; for NSEC3 the owner may not even be knowable.
 * @param type for stale-serving.
 */
int32_t get_new_ttl(const struct entry_h *entry, const struct kr_query *qry,
                    const knot_dname_t *owner, uint16_t type, uint32_t now);


/* RRset (de)materialization; implementation in ./entry_rr.c */

/** Size of the RR count field */
#define KR_CACHE_RR_COUNT_SIZE sizeof(uint16_t)

/** Compute size of serialized rdataset.  NULL is accepted as empty set. */
static inline int rdataset_dematerialize_size(const knot_rdataset_t *rds)
{
	return KR_CACHE_RR_COUNT_SIZE + (rds == NULL ? 0 : rds->size);
}

/** Analyze the length of a dematerialized rdataset.
 * Note that in the data it's KR_CACHE_RR_COUNT_SIZE and then this returned size. */
static inline int rdataset_dematerialized_size(const uint8_t *data, uint16_t *rdataset_count)
{
	uint16_t count;
	assert(sizeof(count) == KR_CACHE_RR_COUNT_SIZE);
	memcpy(&count, data, sizeof(count));
	const uint8_t *rdata = data + sizeof(count);
	if (rdataset_count) // memcpy is safe for unaligned case (on non-x86)
		memcpy(rdataset_count, &count, sizeof(count));
	for (int i = 0; i < count; ++i) {
		__typeof__(((knot_rdata_t *)NULL)->len) len; // memcpy as above
		memcpy(&len, rdata + offsetof(knot_rdata_t, len), sizeof(len));
		rdata += knot_rdata_size(len);
	}
	return rdata - (data + sizeof(count));
}

/** Serialize an rdataset. */
int rdataset_dematerialize(const knot_rdataset_t *rds, uint8_t * restrict data);


/** Partially constructed answer when gathering RRsets from cache. */
struct answer {
	int rcode;		/**< PKT_NODATA, etc. */
	struct nsec_p nsec_p;	/**< Don't mix different NSEC* parameters in one answer. */
	knot_mm_t *mm;		/**< Allocator for rrsets */
	struct answer_rrset {
		ranked_rr_array_entry_t set;	/**< set+rank for the main data */
		knot_rdataset_t sig_rds;	/**< RRSIG data, if any */
	} rrsets[1+1+3]; /**< see AR_ANSWER and friends; only required records are filled */
};
enum {
	AR_ANSWER = 0, /**< Positive answer record.  It might be wildcard-expanded. */
	AR_SOA,  /**< SOA record. */
	AR_NSEC, /**< NSEC* covering or matching the SNAME (next closer name in NSEC3 case). */
	AR_WILD, /**< NSEC* covering or matching the source of synthesis. */
	AR_CPE,  /**< NSEC3 matching the closest provable encloser. */
};

/** Materialize RRset + RRSIGs into ans->rrsets[id].
 * LATER(optim.): it's slightly wasteful that we allocate knot_rrset_t for the packet
 *
 * \return error code.  They are all bad conditions and "guarded" by assert.
 */
int entry2answer(struct answer *ans, int id,
		const struct entry_h *eh, const uint8_t *eh_bound,
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



/* NSEC (1) stuff.  Implementation in ./nsec1.c */

/** Construct a string key for for NSEC (1) predecessor-search.
 * \param add_wildcard Act as if the name was extended by "*."
 * \note k->zlf_len is assumed to have been correctly set */
knot_db_val_t key_NSEC1(struct key *k, const knot_dname_t *name, bool add_wildcard);

/** Closest encloser check for NSEC (1).
 * To understand the interface, see the call point.
 * \param k	space to store key + input: zname and zlf_len
 * \return 0: success;  >0: try other (NSEC3);  <0: exit cache immediately. */
int nsec1_encloser(struct key *k, struct answer *ans,
		   const int sname_labels, int *clencl_labels,
		   knot_db_val_t *cover_low_kwz, knot_db_val_t *cover_hi_kwz,
		   const struct kr_query *qry, struct kr_cache *cache);

/** Source of synthesis (SS) check for NSEC (1).
 * To understand the interface, see the call point.
 * \return 0: continue; <0: exit cache immediately;
 * 	AR_SOA: skip to adding SOA (SS was covered or matched for NODATA). */
int nsec1_src_synth(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    knot_db_val_t cover_low_kwz, knot_db_val_t cover_hi_kwz,
		    const struct kr_query *qry, struct kr_cache *cache);


/* NSEC3 stuff.  Implementation in ./nsec3.c */

/** Construct a string key for for NSEC3 predecessor-search, from an NSEC3 name.
 * \note k->zlf_len is assumed to have been correctly set */
knot_db_val_t key_NSEC3(struct key *k, const knot_dname_t *nsec3_name,
			const nsec_p_hash_t nsec_p_hash);

/** TODO.  See nsec1_encloser(...) */
int nsec3_encloser(struct key *k, struct answer *ans,
		   const int sname_labels, int *clencl_labels,
		   const struct kr_query *qry, struct kr_cache *cache);

/** TODO.  See nsec1_src_synth(...) */
int nsec3_src_synth(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    const struct kr_query *qry, struct kr_cache *cache);



#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "cach",  ## __VA_ARGS__)

/** Shorthand for operations on cache backend */
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, &(cache)->stats, ## __VA_ARGS__)


static inline uint16_t get_uint16(const void *address)
{
	uint16_t tmp;
	memcpy(&tmp, address, sizeof(tmp));
	return tmp;
}

/** Useful pattern, especially as void-pointer arithmetic isn't standard-compliant. */
static inline uint8_t * knot_db_val_bound(knot_db_val_t val)
{
	return (uint8_t *)val.data + val.len;
}

