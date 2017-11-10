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

#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <libknot/errcode.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/ucw/lib.h"
#include "contrib/cleanup.h"
#include "lib/cache.h"
#include "lib/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/utils.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE((qry), "cach",  fmt)

/** Cache version */
static const uint16_t CACHE_VERSION = 1;
/** Key size */
#define KEY_HSIZE (sizeof(uint8_t) + sizeof(uint16_t))
#define KEY_SIZE (KEY_HSIZE + KNOT_DNAME_MAXLEN)

/** Short-time "no data" retention to avoid bursts */
static const uint32_t DEFAULT_MINTTL = 5;

/* Shorthand for operations on cache backend */
#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, ## __VA_ARGS__)

/** @internal Removes all records from cache. */
static inline int cache_clear(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version */
	uint8_t key_str[] = "\x00\x00V"; /* CACHE_KEY_DEF; zero-term. but we don't care */
	knot_db_val_t key = { .data = key_str, .len = sizeof(key_str) };
	knot_db_val_t val = { };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret == 0 && val.len == sizeof(CACHE_VERSION)
	    && memcmp(val.data, &CACHE_VERSION, sizeof(CACHE_VERSION)) == 0) {
		ret = kr_error(EEXIST);
	} else {
		int oldret = ret;
		/* Version doesn't match. Recreate cache and write version key. */
		ret = cache_op(cache, count);
		if (ret != 0) { /* Non-empty cache, purge it. */
			kr_log_info("[     ][cach] incompatible cache database detected, purging\n");
			if (oldret) {
				kr_log_verbose("bad ret: %d\n", oldret);
			} else if (val.len != sizeof(CACHE_VERSION)) {
				kr_log_verbose("bad length: %d\n", (int)val.len);
			} else {
				uint16_t ver;
				memcpy(&ver, val.data, sizeof(ver));
				kr_log_verbose("bad version: %d\n", (int)ver);
			}
			ret = cache_clear(cache);
		}
		/* Either purged or empty. */
		if (ret == 0) {
			/* Key/Val is invalidated by cache purge, recreate it */
			val.data = /*const-cast*/(void *)&CACHE_VERSION;
			val.len = sizeof(CACHE_VERSION);
			ret = cache_op(cache, write, &key, &val, 1);
		}
	}
	kr_cache_sync(cache);
	return ret;
}

int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	/* Open cache */
	if (!api) {
		api = kr_cdb_lmdb();
	}
	cache->api = api;
	int ret = cache->api->open(&cache->db, opts, mm);
	if (ret != 0) {
		return ret;
	}
	memset(&cache->stats, 0, sizeof(cache->stats));
	cache->ttl_min = 0;
	cache->ttl_max = KR_CACHE_DEFAULT_MAXTTL;
	/* Check cache ABI version */
	(void) assert_right_version(cache);
	return 0;
}

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
}

int kr_cache_sync(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	if (cache->api->sync) {
		return cache_op(cache, sync);
	}
	return kr_ok();
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_clear(cache);
	if (ret == 0) {
		ret = assert_right_version(cache);
	}
	return ret;
}


#include "lib/dnssec/nsec.h"
#include "lib/dnssec/ta.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"



/** Cache entry header
 *
 * 'E' entry (exact hit):
 *	- ktype == NS: multiple chained entry_h, based on has_* : 1 flags;
 *		TODO: NSEC3 chain descriptors (iff nsec3_cnt > 0)
 *	- is_packet: uint16_t length, otherwise opaque ATM;
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

struct nsec_p {
	struct {
		uint8_t salt_len;
		uint8_t alg;
		uint16_t iters;
	} s;
	uint8_t *salt;
};

/** Check basic consistency of entry_h, not looking into ->data.
 * \note only exact hits and NSEC1 are really considered ATM. */
static struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t ktype)
{
	/* Length checks. */
	if (data.len < offsetof(struct entry_h, data))
		return NULL;
	const struct entry_h *eh = data.data;
	if (eh->is_packet) {
		uint16_t pkt_len;
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)) {
			return NULL;
		}
		memcpy(&pkt_len, eh->data, sizeof(pkt_len));
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)
				+ pkt_len) {
			return NULL;
		}
	}

	bool ok = true;
	ok = ok && (!kr_rank_test(eh->rank, KR_RANK_BOGUS)
		    || eh->is_packet);

	switch (ktype) {
	case KNOT_RRTYPE_NSEC:
		ok = ok && !(eh->is_packet || eh->has_ns || eh->has_cname
				|| eh->has_dname);
		break;
	default:
		if (eh->is_packet)
			ok = ok && !kr_rank_test(eh->rank, KR_RANK_SECURE);
	}

	//LATER: rank sanity
	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}


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


static int32_t get_new_ttl(const struct entry_h *entry, uint32_t current_time)
{
	int32_t diff = current_time - entry->time;
	if (diff < 0) {
		/* We may have obtained the record *after* the request started. */
		diff = 0;
	}
	int32_t res = entry->ttl - diff;
	VERBOSE_MSG(NULL, "TTL remains: %d\n", (int)res);
	return res;
}
int32_t kr_cache_ttl(const struct kr_cache_p *peek, uint32_t current_time)
{
	const struct entry_h *eh = peek->raw_data;
	return get_new_ttl(eh, current_time);
}

/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static bool is_expiring(uint32_t orig_ttl, uint32_t new_ttl)
{
	int64_t nttl = new_ttl; /* avoid potential over/under-flow */
	return 100 * (nttl - 5) < orig_ttl;
}




/* forwards for larger chunks of code */

static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry);
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank);
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k);




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



/* TODO: move rdataset_* and pkt_* functions into a separate c-file. */
/** Materialize a knot_rdataset_t from cache with given TTL.
 * Return the number of bytes consumed or an error code.
 */
static int rdataset_materialize(knot_rdataset_t * restrict rds, const void *data,
		const void *data_bound, uint32_t ttl, knot_mm_t *pool)
{
	assert(rds && data && data_bound && data_bound > data && !rds->data);
	const void *d = data; /* iterates over the cache data */
	{
		uint8_t rr_count;
		memcpy(&rr_count, d++, sizeof(rr_count));
		rds->rr_count = rr_count;
	}
	/* First sum up the sizes for wire format length. */
	size_t rdata_len_sum = 0;
	for (int i = 0; i < rds->rr_count; ++i) {
		if (d + 2 > data_bound) {
			VERBOSE_MSG(NULL, "materialize: EILSEQ!\n");
			return kr_error(EILSEQ);
		}
		uint16_t len;
		memcpy(&len, d, sizeof(len));
		d += sizeof(len) + len;
		rdata_len_sum += len;
	}
	/* Each item in knot_rdataset_t needs TTL (4B) + rdlength (2B) + rdata */
	rds->data = mm_alloc(pool, rdata_len_sum + ((size_t)rds->rr_count) * (4 + 2));
	if (!rds->data) {
		return kr_error(ENOMEM);
	}
	/* Construct the output, one "RR" at a time. */
	d = data + 1/*sizeof(rr_count)*/;
	knot_rdata_t *d_out = rds->data; /* iterates over the output being materialized */
	for (int i = 0; i < rds->rr_count; ++i) {
		uint16_t len;
		memcpy(&len, d, sizeof(len));
		d += sizeof(len);
		knot_rdata_init(d_out, len, d, ttl);
		d += len;
		//d_out = kr_rdataset_next(d_out);
		d_out += 4 + 2 + len; /* TTL + rdlen + rdata */
	}
	VERBOSE_MSG(NULL, "materialized from %d B\n", (int)(d - data));
	return d - data;
}

int kr_cache_materialize(knot_rdataset_t *dst, const struct kr_cache_p *ref,
			 uint32_t new_ttl, knot_mm_t *pool)
{
	struct entry_h *eh = ref->raw_data;
	return rdataset_materialize(dst, eh->data, ref->raw_bound, new_ttl, pool);
}


/** Materialize RRset + RRSIGs into ans->rrsets[id].
 * LATER(optim.): it's slightly wasteful that we allocate knot_rrset_t for the packet
 */
static int entry2answer(struct answer *ans, int id,
		const struct entry_h *eh, const void *eh_bound,
		const knot_dname_t *owner, uint16_t type, uint32_t new_ttl)
{
	/* We assume it's zeroed.  Do basic sanity check. */
	if (ans->rrsets[id].set.rr || ans->rrsets[id].sig_rds.data
	    || (type == KNOT_RRTYPE_NSEC && ans->nsec_v != 1)
	    || (type == KNOT_RRTYPE_NSEC3 && ans->nsec_v != 3)) {
		assert(false);
		return kr_error(EINVAL);
	}
	/* Materialize the base RRset. */
	knot_rrset_t *rr = ans->rrsets[id].set.rr
		= knot_rrset_new(owner, type, KNOT_CLASS_IN, ans->mm);
	if (!rr) return kr_error(ENOMEM);
	int ret = rdataset_materialize(&rr->rrs, eh->data, eh_bound, new_ttl, ans->mm);
	if (ret < 0) goto fail;
	size_t data_off = ret;
	ans->rrsets[id].set.rank = eh->rank;
	ans->rrsets[id].set.expiring = is_expiring(eh->ttl, new_ttl);
	/* Materialize the RRSIG RRset for the answer in (pseudo-)packet. */
	bool want_rrsigs = kr_rank_test(eh->rank, KR_RANK_SECURE);
			//^^ TODO: vague; function parameter instead?
	if (want_rrsigs) {
		ret = rdataset_materialize(&ans->rrsets[id].sig_rds, eh->data + data_off,
					   eh_bound, new_ttl, ans->mm);
		if (ret < 0) goto fail;

		// TODO
		#if 0
		/* sanity check: we consumed exactly all data */
		int unused_bytes = eh_bound - (void *)eh->data - data_off - ret;
		if (ktype != KNOT_RRTYPE_NS && unused_bytes) {
			/* ^^ it doesn't have to hold in multi-RRset entries; LATER: more checks? */
			VERBOSE_MSG(qry, "BAD?  Unused bytes: %d\n", unused_bytes);
		}
		#endif
	}
	return kr_ok();
fail:
	/* Cleanup the item that we might've (partially) written to. */
	knot_rrset_free(&ans->rrsets[id].set.rr, ans->mm);
	knot_rdataset_clear(&ans->rrsets[id].sig_rds, ans->mm);
	memset(&ans->rrsets[id], 0, sizeof(ans->rrsets[id]));
	return kr_error(ret);
}



/** Compute size of dematerialized rdataset.  NULL is accepted as empty set. */
static int rdataset_dematerialize_size(const knot_rdataset_t *rds)
{
	return 1/*sizeof(rr_count)*/ + (rds
		? knot_rdataset_size(rds) - 4 * rds->rr_count /*TTLs*/
		: 0);
}
/** Dematerialize a rdataset. */
static int rdataset_dematerialize(const knot_rdataset_t *rds, void * restrict data)
{
	assert(data);
	if (rds && rds->rr_count > 255) {
		return kr_error(ENOSPC);
	}
	uint8_t rr_count = rds ? rds->rr_count : 0;
	memcpy(data++, &rr_count, sizeof(rr_count));

	knot_rdata_t *rd = rds->data;
	for (int i = 0; i < rr_count; ++i, rd = kr_rdataset_next(rd)) {
		uint16_t len = knot_rdata_rdlen(rd);
		memcpy(data, &len, sizeof(len));
		data += sizeof(len);
		memcpy(data, knot_rdata_data(rd), len);
		data += len;
	}
	return kr_ok();
}

/** Given a valid entry header, find its length (i.e. offset of the next entry).
 * \param val The beginning of the data and the bound (read only).
 */
static int entry_h_len(const knot_db_val_t val)
{
	const bool ok = val.data && ((ssize_t)val.len) > 0;
	if (!ok) return kr_error(EINVAL);
	const struct entry_h *eh = val.data;
	const void *d = eh->data; /* iterates over the data in entry */
	const void *data_bound = val.data + val.len;
	if (d >= data_bound) return kr_error(EILSEQ);
	if (!eh->is_packet) { /* Positive RRset + its RRsig set (may be empty). */
		int sets = 2;
		while (sets-- > 0) {
			if (d + 1 > data_bound) return kr_error(EILSEQ);
			uint8_t rr_count;
			memcpy(&rr_count, d++, sizeof(rr_count));
			for (int i = 0; i < rr_count; ++i) {
				if (d + 2 > data_bound) return kr_error(EILSEQ);
				uint16_t len;
				memcpy(&len, d, sizeof(len));
				d += 2 + len;
			}
		}
	} else { /* A "packet" (opaque ATM). */
		if (d + 2 > data_bound) return kr_error(EILSEQ);
		uint16_t len;
		memcpy(&len, d, sizeof(len));
		d += 2 + len;
	}
	if (d > data_bound) return kr_error(EILSEQ);
	return d - val.data;
}

/** There may be multiple entries within, so rewind `val` to the one we want.
 *
 * ATM there are multiple types only for the NS ktype.
 * \return error code
 */
static int entry_h_seek(knot_db_val_t *val, uint16_t type)
{
	uint16_t ktype;
	switch (type) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		ktype = KNOT_RRTYPE_NS;
	default:
		ktype = type;
	}
	if (ktype != KNOT_RRTYPE_NS) {
		return kr_ok();
	}
	const struct entry_h *eh = entry_h_consistent(*val, ktype);
	if (!eh) {
		return kr_error(EILSEQ);
	}

	bool present;
	switch (type) {
	case KNOT_RRTYPE_NS:
		present = eh->has_ns;
		break;
	case KNOT_RRTYPE_CNAME:
		present = eh->has_cname;
		break;
	case KNOT_RRTYPE_DNAME:
		present = eh->has_dname;
		break;
	default:
		return kr_error(EINVAL);
	}
	if (!present) {
		return kr_error(ENOENT);
	}
	/* count how many entries to skip */
	int to_skip = 0;
	switch (type) {
	case KNOT_RRTYPE_DNAME:
		to_skip += eh->has_cname;
	case KNOT_RRTYPE_CNAME:
		to_skip += eh->has_ns;
	case KNOT_RRTYPE_NS:
		break;
	}
	/* advance `val` and `eh` */
	while (to_skip-- > 0) {
		int len = entry_h_len(*val);
		if (len < 0 || len > val->len) {
			return kr_error(len < 0 ? len : EILSEQ);
			// LATER: recovery, perhaps via removing the entry?
		}
		val->data += len;
		val->len -= len;
	}
	return kr_ok();
}

/**
 */
int pkt_renew(knot_pkt_t *pkt, const knot_dname_t *name, uint16_t type)
{
	/* Update packet question if needed. */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)
	    || knot_pkt_qtype(pkt) != type || knot_pkt_qclass(pkt) != KNOT_CLASS_IN) {
		int ret = kr_pkt_recycle(pkt);
		if (ret) return kr_error(ret);
		ret = knot_pkt_put_question(pkt, name, KNOT_CLASS_IN, type);
		if (ret) return kr_error(ret);
	}

	pkt->parsed = pkt->size = PKT_SIZE_NOWIRE;
	knot_wire_set_qr(pkt->wire);
	knot_wire_set_aa(pkt->wire);
	return kr_ok();
}

/** Reserve space for additional `count` RRsets.
 * \note pkt->rr_info gets correct length but is always zeroed
 */
int pkt_alloc_space(knot_pkt_t *pkt, int count)
{
	size_t allocd_orig = pkt->rrset_allocd;
	if (pkt->rrset_count + count <= allocd_orig) {
		return kr_ok();
	}
	/* A simple growth strategy, amortized O(count). */
	pkt->rrset_allocd = MAX(
			pkt->rrset_count + count,
			pkt->rrset_count + allocd_orig);

	pkt->rr = mm_realloc(&pkt->mm, pkt->rr,
				sizeof(pkt->rr[0]) * pkt->rrset_allocd,
				sizeof(pkt->rr[0]) * allocd_orig);
	if (!pkt->rr) {
		return kr_error(ENOMEM);
	}
	/* Allocate pkt->rr_info to be certain, but just leave it zeroed. */
	mm_free(&pkt->mm, pkt->rr_info);
	pkt->rr_info = mm_alloc(&pkt->mm, sizeof(pkt->rr_info[0]) * pkt->rrset_allocd);
	if (!pkt->rr_info) {
		return kr_error(ENOMEM);
	}
	memset(pkt->rr_info, 0, sizeof(pkt->rr_info[0]) * pkt->rrset_allocd);
	return kr_ok();
}

/** Append RRset + its RRSIGs into the current section (*shallow* copy), with given rank.
 * \note it works with empty set as well (skipped).
 * \note KNOT_CLASS_IN is assumed
 */
int pkt_append(knot_pkt_t *pkt, const struct answer_rrset *rrset, uint8_t rank)
{
	/* allocate space, to be sure */
	int rrset_cnt = (rrset->set.rr->rrs.rr_count > 0) + (rrset->sig_rds.rr_count > 0);
	int ret = pkt_alloc_space(pkt, rrset_cnt);
	if (ret) return kr_error(ret);
	/* write both sets */
	const knot_rdataset_t *rdss[2] = { &rrset->set.rr->rrs, &rrset->sig_rds };
	for (int i = 0; i < rrset_cnt; ++i) {
		assert(rdss[i]->rr_count);
		/* allocate rank */
		uint8_t *rr_rank = mm_alloc(&pkt->mm, sizeof(*rr_rank));
		if (!rr_rank) return kr_error(ENOMEM);
		*rr_rank = (i == 0) ? rank : (KR_RANK_INITIAL | KR_RANK_AUTH);
			/* rank for RRSIGs isn't really useful: ^^ */
		if (i == 0) {
			pkt->rr[pkt->rrset_count] = *rrset->set.rr;
			pkt->rr[pkt->rrset_count].additional = rr_rank;
		} else {
		/* append the RR array */
			pkt->rr[pkt->rrset_count] = (knot_rrset_t){
				.owner = knot_dname_copy(rrset->set.rr->owner, &pkt->mm),
					/* ^^ well, another copy isn't really needed */
				.type = KNOT_RRTYPE_RRSIG,
				.rclass = KNOT_CLASS_IN,
				.rrs = *rdss[i],
				.additional = rr_rank,
			};
		}
		++pkt->rrset_count;
		++(pkt->sections[pkt->current].count);
	}
	return kr_ok();
}

/* end of TODO */



/** Check that no label contains a zero character.
 *
 * We refuse to work with those, as LF and our cache keys might become ambiguous.
 * Assuming uncompressed name, as usual.
 * CACHE_KEY_DEF
 */
static bool check_dname_for_lf(const knot_dname_t *n)
{
	return knot_dname_size(n) == strlen((const char *)n) + 1;
}

/** Like key_exact_type() but omits a couple checks not holding for pkt cache. */
static knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type)
{
	assert(!knot_rrtype_is_metatype(type));
	switch (type) {
	case KNOT_RRTYPE_RRSIG: /* no RRSIG query caching, at least for now */
		assert(false);
		return (knot_db_val_t){};
	/* xNAME lumped into NS. */
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		type = KNOT_RRTYPE_NS;
	default:
		break;
	}

	int name_len = k->buf[0];
	k->buf[name_len + 1] = 0; /* make sure different names can never match */
	k->buf[name_len + 2] = 'E'; /* tag for exact name+type matches */
	memcpy(k->buf + name_len + 3, &type, 2);
	k->type = type;
	/* CACHE_KEY_DEF: key == dname_lf + '\0' + 'E' + RRTYPE */
	return (knot_db_val_t){ k->buf + 1, name_len + 4 };
}

/** TODO */
static knot_db_val_t key_exact_type(struct key *k, uint16_t type)
{
	switch (type) {
	/* Sanity check: forbidden types represented in other way(s). */
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		assert(false);
		return (knot_db_val_t){};
	}
	return key_exact_type_maypkt(k, type);
}

/** TODO
 * \param add_wildcard Act as if the name was extended by "*."
 */
static knot_db_val_t key_NSEC1(struct key *k, const knot_dname_t *name,
				bool add_wildcard)
{
	/* we basically need dname_lf with two bytes added
	 * on a correct place within the name (the cut) */
	int ret;
	const bool ok = k && name
		&& !(ret = kr_dname_lf(k->buf, name, NULL));
	if (!ok) {
		assert(false);
		return (knot_db_val_t){};
	}

	uint8_t *begin = k->buf + 1 + k->zlf_len; /* one byte after zone's zero */
	uint8_t *end = k->buf + 1 + k->buf[0]; /* we don't use the final zero in key,
						* but move it anyway */
	if (end < begin) {
		assert(false);
		return (knot_db_val_t){};
	}
	int key_len;
	if (end > begin) {
		memmove(begin + 2, begin, end - begin);
		key_len = k->buf[0] + 1;
	} else {
		key_len = k->buf[0] + 2;
	}
	if (add_wildcard) {
		if (end > begin) {
			/* not directly under zone name -> need separator */
			k->buf[1 + key_len++] = 0;
		}
		k->buf[1 + key_len++] = '*';
		k->buf[0] += 2;
	}
	/* CACHE_KEY_DEF: key == zone's dname_lf + 0 + '1' + dname_lf
	 * of the name within the zone without the final 0.  Iff the latter is empty,
	 * there's no zero to cut and thus the key_len difference.
	 */
	begin[0] = 0;
	begin[1] = '1'; /* tag for NSEC1 */

	VERBOSE_MSG(NULL, "<> key_NSEC1; ");
	kr_dname_print(name, "name: ", " ");
	kr_log_verbose("(zone name LF length: %d; total key length: %d)\n",
			k->zlf_len, key_len);

	return (knot_db_val_t){ k->buf + 1, key_len };
}

/**
 * \note k1.data may be NULL, meaning the lower bound shouldn't be checked
 */
static bool kwz_between(knot_db_val_t k1, knot_db_val_t k2, knot_db_val_t k3)
{
	assert(k2.data && k3.data);
	/* CACHE_KEY_DEF; we need to beware of one key being a prefix of another */
	if (k1.data) {
		int cmp12 = memcmp(k1.data, k2.data, MIN(k1.len, k2.len));
		bool ok = cmp12 < 0 || (cmp12 == 0 && k1.len < k2.len);
		if (!ok) return false;
	}
	if (k3.len == 0) { /* wrap-around */
		return k2.len > 0;
	} else {
		int cmp23 = memcmp(k2.data, k3.data, MIN(k2.len, k3.len));
		return cmp23 < 0 || (cmp23 == 0 && k2.len < k3.len);
	}
}

/** NSEC1 range search.
 *
 * \param key Pass output of key_NSEC1(k, ...)
 * \param val[out] The raw data of the NSEC cache record (optional; consistency checked).
 * \param exact_match[out] Whether the key was matched exactly or just covered (optional).
 * \param kwz_low[out] Output the low end of covering NSEC, pointing within `key` (optional).
 * \param kwz_high[in,out] Storage for the high end of covering NSEC (optional).
 * \return Error message or NULL.
 */
static const char * find_leq_NSEC1(struct kr_cache *cache, const struct kr_query *qry,
			knot_db_val_t key, const struct key *k, knot_db_val_t *value,
			bool *exact_match, knot_db_val_t *kwz_low, knot_db_val_t *kwz_high,
			uint32_t *new_ttl)
{
	/* Do the cache operation. */
	const size_t nwz_off = key_nwz_off(k);
	if (!key.data || key.len < nwz_off) {
		assert(false);
		return "range search ERROR";
	}
	knot_db_val_t val = { };
	int ret = cache_op(cache, read_leq, &key, &val);
	if (ret < 0) {
		if (ret == kr_error(ENOENT)) {
			return "range search miss";
		} else {
			assert(false);
			return "range search ERROR";
		}
	}
	if (value) {
		*value = val;
	}
	/* Check consistency, TTL, rank. */
	const bool is_exact = (ret == 0);
	if (exact_match) {
		*exact_match = is_exact;
	}
	const struct entry_h *eh = entry_h_consistent(val, KNOT_RRTYPE_NSEC);
	if (!eh) {
		/* This might be just finding something else than NSEC1 entry,
		 * in case we searched before the very first one in the zone. */
		return "range search found inconsistent entry";
	}
	int32_t new_ttl_ = get_new_ttl(eh, qry->creation_time.tv_sec);
	if (new_ttl_ < 0 || !kr_rank_test(eh->rank, KR_RANK_SECURE)) {
		return "range search found stale or insecure entry";
		/* TODO: remove the stale record *and* retry,
		 * in case we haven't run off.  Perhaps start by in_zone check. */
	}
	if (new_ttl) {
		*new_ttl = new_ttl_;
	}
	if (is_exact) {
		/* Nothing else to do. */
		return NULL;
	}
	/* The NSEC starts strictly before our target name;
	 * check that it's still within the zone and that
	 * it ends strictly after the sought name
	 * (or points to origin). */
	bool in_zone = key.len >= nwz_off
		/* CACHE_KEY_DEF */
		&& memcmp(k->buf + 1, key.data, nwz_off) == 0;
	if (!in_zone) {
		return "range search miss (!in_zone)";
	}
	/* We know it starts before sname, so let's check the other end.
	 * 1. construct the key for the next name - kwz_hi. */
	const knot_dname_t *next = eh->data + 3; /* it's *full* name ATM */
	if (!eh->data[0]) {
		assert(false);
		return "ERROR";
		/* TODO: more checks?  Also, `data + 3` is kinda messy. */
	}
	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> NSEC: next name: ");
		kr_dname_print(next, "", "\n");
	}
	knot_dname_t ch_buf[KNOT_DNAME_MAXLEN];
	knot_dname_t *chs = kwz_high ? kwz_high->data : ch_buf;
	if (!chs) {
		assert(false);
		return "EINVAL";
	}
	ret = kr_dname_lf(chs, next, NULL);
	if (ret) {
		assert(false);
		return "ERROR";
	}
	knot_db_val_t kwz_hi = { /* skip the zone name */
		.data = chs + 1 + k->zlf_len,
		.len = chs[0] - k->zlf_len,
	};
	assert((ssize_t)(kwz_hi.len) >= 0);
	/* 2. do the actual range check. */
	const knot_db_val_t kwz_sname = {
		.data = (void *)k->buf + 1 + nwz_off,
		.len = k->buf[0] - k->zlf_len,
	};
	assert((ssize_t)(kwz_sname.len) >= 0);
	bool covers = kwz_between((knot_db_val_t){} /*we know it's before*/,
				  kwz_sname, kwz_hi);
	if (!covers) {
		return "range search miss (!covers)";
	}
	/* Output data. */
	if (kwz_low) {
		*kwz_low = (knot_db_val_t){
			.data = key.data + nwz_off,
			.len = key.len - nwz_off,
		};	/* CACHE_KEY_DEF */
	}
	if (kwz_high) {
		*kwz_high = kwz_hi;
	}
	return NULL;
}

/** Reconstruct a name into a buffer (assuming length at least KNOT_DNAME_MAXLEN). */
int dname_wire_reconstruct(knot_dname_t *buf, const struct key *k,
			   knot_db_val_t kwz)
{
	/* Reconstruct from key: first the ending, then zone name. */
	int ret = knot_dname_lf2wire(buf, kwz.len, kwz.data);
	if (ret < 0) {
		VERBOSE_MSG(NULL, "=> NSEC: LF2wire ret = %d\n", ret);
		assert(false);
		return ret;
	}
	ret = knot_dname_to_wire(buf + ret, k->zname, KNOT_DNAME_MAXLEN - kwz.len);
	if (ret != k->zlf_len + 1) {
		assert(false);
		return ret < 0 ? ret : kr_error(EILSEQ);
	}
	return kr_ok();
}


static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);

/** function for .produce phase */
int cache_lmdb_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || qry->flags.NO_CACHE
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state; /* Already resolved/failed or already tried, etc. */
	}
	/* ATM cache only peeks for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * TODO Note: it's important to skip this if rrcache sets KR_STATE_DONE,
	 * as CNAME chains need more iterations to get fetched. */
	qry->flags.NO_CACHE = true;

	struct key k_storage, *k = &k_storage;
	if (!check_dname_for_lf(qry->sname)) {
		return ctx->state;
	}
	int ret = kr_dname_lf(k->buf, qry->sname, NULL);
	if (ret) {
		return KR_STATE_FAIL;
	}

	const uint8_t lowest_rank = get_lowest_rank(req, qry);
	// FIXME: the whole approach to +cd answers

	/** 1. find the name or the closest (available) zone, not considering wildcards
	 *  1a. exact name+type match (can be negative answer in insecure zones)
	 */
	if (qry->stype == KNOT_RRTYPE_RRSIG) {
		return ctx->state; /* LATER: some other behavior for this STYPE? */
	}
	knot_db_val_t key = key_exact_type_maypkt(k, qry->stype);
	knot_db_val_t val = { };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		/* found an entry: test conditions, materialize into pkt, etc. */
		ret = found_exact_hit(ctx, pkt, val, lowest_rank);
	}
	if (ret && ret != -abs(ENOENT)) {
		VERBOSE_MSG(qry, "=> exact hit error: %d %s\n",
				ret, strerror(abs(ret)));
		assert(false);
		return ctx->state;
	} else if (!ret) {
		VERBOSE_MSG(qry, "=> satisfied from cache (direct hit)\n");
		return KR_STATE_DONE;
	}

	/** 1b. otherwise, find the longest prefix NS/xNAME (with OK time+rank). [...] */
	k->zname = qry->sname;
	if (qry->stype == KNOT_RRTYPE_DS) { /* DS is parent-side. */
		k->zname = knot_wire_next_label(k->zname, NULL);
		if (!k->zname) {
			return ctx->state; /* can't go above root */
		}
	}
	kr_dname_lf(k->buf, k->zname, NULL); /* LATER(optim.): probably remove */
	const knot_db_val_t val_cut = closest_NS(ctx, k);
	if (!val_cut.data) {
		VERBOSE_MSG(qry, "=> not even root NS in cache\n");
		return ctx->state; /* nothing to do without any NS at all */
	}
	switch (k->type) {
	case KNOT_RRTYPE_NS:
		VERBOSE_MSG(qry, "=> trying zone: ");
		kr_dname_print(k->zname, "", "\n");
		break;
	case KNOT_RRTYPE_CNAME:
		ret = answer_simple_hit(ctx, pkt, KNOT_RRTYPE_CNAME, val_cut.data,
				val_cut.data + val_cut.len,
				get_new_ttl(val_cut.data, qry->creation_time.tv_sec));
		/* TODO: ^^ cumbersome code */
		if (ret == kr_ok()) {
			VERBOSE_MSG(qry, "=> satisfied by CNAME\n");
			return KR_STATE_DONE;
		} else {
			return ctx->state;
		}

	case KNOT_RRTYPE_DNAME:
		VERBOSE_MSG(qry, "=> DNAME not supported yet\n"); // LATER
		return ctx->state;
	default:
		assert(false);
	}

#if 0
	if (!eh) { /* fall back to root hints? */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret) return KR_STATE_FAIL;
		assert(!qry->zone_cut.parent);

		//VERBOSE_MSG(qry, "=> using root hints\n");
		//qry->flags.AWAIT_CUT = false;
		return ctx->state;
	}

	/* Now `eh` points to the closest NS record that we've found,
	 * and that's the only place to start - we may either find
	 * a negative proof or we may query upstream from that point. */
	kr_zonecut_set(&qry->zone_cut, k->zname);
	ret = kr_make_query(qry, pkt); // FIXME: probably not yet - qname minimization
	if (ret) return KR_STATE_FAIL;

	/* Note: up to here we can run on any cache backend,
	 * without touching the code. */
	if (!eh->nsec1_pos) {
		/* No NSEC1 RRs for this zone in cache. */
		/* TODO: NSEC3 */
		//VERBOSE_MSG(qry, "   no NSEC1\n");
		//return ctx->state;
	}
#endif

	/* collecting multiple NSEC* + RRSIG records, in preparation for the answer
	 *  + track the progress
	 */
	struct answer ans = {};
	ans.mm = &pkt->mm;

	/* Start of NSEC* covering the sname;
	 * it's part of key - the one within zone (read only) */
	knot_dname_t cover_hi_storage[KNOT_DNAME_MAXLEN];
	knot_db_val_t cover_low_kwz = {};
	knot_db_val_t cover_hi_kwz = {
		.data = cover_hi_storage,
		.len = sizeof(cover_hi_storage),
	};

	/** 2. closest (provable) encloser.
	 * iterate over all NSEC* chain parameters
	 */
	int clencl_labels = -1;
	//while (true) { //for (int i_nsecp = 0; i
	// TODO(NSEC3): better signalling when to "continue;" and when to "break;"
	// incl. clearing partial answers in `ans`
		//assert(eh->nsec1_pos <= 1);
		int nsec = 1;
		switch (nsec) {
		case 1: {
 			/* find a previous-or-equal name+NSEC in cache covering
			 * the QNAME, checking TTL etc. */

			ans.nsec_v = 1;
			//nsec_leq()
			knot_db_val_t key = key_NSEC1(k, qry->sname, false);
			knot_db_val_t val = {};
			bool exact_match;
			uint32_t new_ttl;
			const char *err = find_leq_NSEC1(cache, qry, key, k, &val,
					&exact_match, &cover_low_kwz, &cover_hi_kwz, &new_ttl);
			if (err) {
				VERBOSE_MSG(qry, "=> NSEC: %s\n", err);
				break;
			}

			const struct entry_h *nsec_eh = val.data;
			const void *nsec_eh_bound = val.data + val.len;

			/* Get owner name of the record. */ //WILD: different, expanded owner
			const knot_dname_t *owner;
			knot_dname_t owner_buf[KNOT_DNAME_MAXLEN];
			if (exact_match) {
				owner = qry->sname;
			} else {
				ret = dname_wire_reconstruct(owner_buf, k, cover_low_kwz);
				if (ret) break;
				owner = owner_buf;
			}

			/* Basic checks OK -> materialize data. */
			ret = entry2answer(&ans, AR_NSEC, nsec_eh, nsec_eh_bound,
					   owner, KNOT_RRTYPE_NSEC, new_ttl);
			if (ret) break;
			VERBOSE_MSG(qry, "=> NSEC: materialized OK\n");

			const knot_rrset_t *nsec_rr = ans.rrsets[AR_NSEC].set.rr;
			if (exact_match) {
				uint8_t *bm = NULL;
				uint16_t bm_size;
				knot_nsec_bitmap(&nsec_rr->rrs,
						 &bm, &bm_size);
				if (!bm || kr_nsec_bitmap_contains_type(bm, bm_size, qry->stype)) {
					assert(bm);
					VERBOSE_MSG(qry, "=> NSEC: exact match, but failed type check\n");
					break; /* exact positive answer should exist! */
				}
				/* NODATA proven; just need to add SOA+RRSIG later */
				VERBOSE_MSG(qry, "=> NSEC: exact match proved NODATA\n");
				ans.rcode = PKT_NODATA;
				break;
			} else { /* inexact match; NXDOMAIN proven *except* for wildcards */
				VERBOSE_MSG(qry, "=> NSEC: exact match covered\n");
				ans.rcode = PKT_NXDOMAIN;
				/* Find label count of the closest encloser.
				 * Both points in an NSEC do exist and any prefixes
				 * of those names as well (empty non-terminals),
				 * but nothing else does inside this "triangle".
				 */
				clencl_labels = MAX(
					knot_dname_matched_labels(nsec_rr->owner, qry->sname),
					knot_dname_matched_labels(qry->sname, knot_nsec_next(&nsec_rr->rrs))
					);
				break;
			}

			}
		case 3: //TODO NSEC3
		default:
			assert(false);
		}
	//}

	if (!ans.rcode) {
		/* Nothing suitable found. */
		return ctx->state;
	}

	/** 3. wildcard checks, in case we found non-existence.
	 */
	if (ans.rcode == PKT_NODATA) {
		/* no wildcard checks needed */
		assert(ans.nsec_v == 1); // for now

	} else if (ans.nsec_v == 1 && ans.rcode == PKT_NXDOMAIN) {
		/* First try to prove that source of synthesis doesn't exist either. */
		/* Construct key for the source of synthesis. */
		const knot_dname_t *ss_name = qry->sname;
		for (int l = knot_dname_labels(qry->sname, NULL); l > clencl_labels; --l)
			ss_name = knot_wire_next_label(ss_name, NULL);
		key = key_NSEC1(k, ss_name, true);
		const size_t nwz_off = key_nwz_off(k);
		if (!key.data || key.len < nwz_off) {
			assert(false);
			return ctx->state;
		}
		knot_db_val_t kwz = {
			.data = key.data + nwz_off,
			.len = key.len - nwz_off,
		};
		assert((ssize_t)(kwz.len) >= 0);
		/* If our covering NSEC already covers it as well, we're fine. */
		if (kwz_between(cover_low_kwz, kwz, cover_hi_kwz)) {
			VERBOSE_MSG(qry, "=> NSEC: covering RR covers also wildcard\n");
			goto do_soa;
		}
		/* Try to find the NSEC */
		knot_db_val_t val = {};
		knot_db_val_t wild_low_kwz = {};
		bool exact_match;
		uint32_t new_ttl;
		const char *err = find_leq_NSEC1(cache, qry, key, k, &val,
				&exact_match, &wild_low_kwz, NULL, &new_ttl);
		if (err) {
			VERBOSE_MSG(qry, "=> NSEC: wildcard proof - %s\n", err);
			return ctx->state;
		}
		/* Materialize the record into answer (speculatively). */
		const struct entry_h *nsec_eh = val.data;
		const void *nsec_eh_bound = val.data + val.len;
		knot_dname_t owner[KNOT_DNAME_MAXLEN];
		ret = dname_wire_reconstruct(owner, k, wild_low_kwz);
		if (ret) return ctx->state;
		ret = entry2answer(&ans, AR_WILD, nsec_eh, nsec_eh_bound,
				   owner, KNOT_RRTYPE_NSEC, new_ttl);
		if (ret) return ctx->state;
		if (!exact_match) {
			/* We have a record proving wildcard non-existence. */
			VERBOSE_MSG(qry, "=> NSEC: wildcard non-existence proof materialized OK\n");
			goto do_soa; /* decrease indentation */
		}
		/* The wildcard exists.  Find if it's NODATA. */
		const knot_rrset_t *nsec_rr = ans.rrsets[AR_WILD].set.rr;
		uint8_t *bm = NULL;
		uint16_t bm_size;
		knot_nsec_bitmap(&nsec_rr->rrs, &bm, &bm_size);
		if (!bm) {
			assert(false);
			return ctx->state;
		}
		if (!kr_nsec_bitmap_contains_type(bm, bm_size, qry->stype)) {
			/* NODATA proven; just need to add SOA+RRSIG later */
			VERBOSE_MSG(qry, "=> NSEC: exact match proved NODATA\n");
			ans.rcode = PKT_NODATA;
		} else {
			/* The data should exist -> don't add this NSEC
			 * and (later) try to find the real wildcard data */
			VERBOSE_MSG(qry, "=> NSEC: wildcard should exist\n");
			knot_rrset_free(&ans.rrsets[AR_WILD].set.rr, &pkt->mm);
			knot_rdataset_clear(&ans.rrsets[AR_WILD].sig_rds, &pkt->mm);
			ans.rcode = PKT_NOERROR;
		}

	} else {
		//TODO NSEC3
		assert(false);
	}


	/** We need to find wildcarded answer. (common for NSEC*)
	 */
	if (ans.rcode == PKT_NOERROR) {
		//TODO let's say we don't support that for now
		return ctx->state;
		/* Construct key for exact qry->stype + source of synthesis. */
		/* Find the record and put it into answer. */
		/* Possibly reuse/generalize (parts of) found_exact_hit(). */
	}


	/** 4. add SOA iff needed
	 */
do_soa:
	if (ans.rcode != PKT_NOERROR) {
		/* assuming k->buf still starts with zone's prefix */
		k->buf[0] = k->zlf_len;
		key = key_exact_type(k, KNOT_RRTYPE_SOA);
		knot_db_val_t val = { };
		ret = cache_op(cache, read, &key, &val, 1);
		const struct entry_h *eh;
		if (ret || !(eh = entry_h_consistent(val, KNOT_RRTYPE_SOA))) {
			return ctx->state;
		}
		void *eh_data_bound = val.data + val.len;

		int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
			return ctx->state;
		}
		ret = entry2answer(&ans, AR_SOA, eh, eh_data_bound,
				   k->zname, KNOT_RRTYPE_SOA, new_ttl);
		if (ret) return ctx->state;
		VERBOSE_MSG(qry, "=> added SOA\n");
	}


	/* Find our target RCODE. */
	int real_rcode;
	switch (ans.rcode) {
	case PKT_NODATA:
		real_rcode = KNOT_RCODE_NOERROR;
		break;
	case PKT_NXDOMAIN:
		real_rcode = KNOT_RCODE_NXDOMAIN;
		break;
	default:
		assert(false);
	case 0: /* i.e. PKT_NOERROR; nothing was found */
		/* LATER(optim.): zone cut? */
		VERBOSE_MSG(qry, "=> negative cache miss\n");
		return ctx->state;
	}

	if (pkt_renew(pkt, qry->sname, qry->stype)
	    || knot_pkt_begin(pkt, KNOT_ANSWER)
	   ) {
		assert(false);
		return ctx->state;
	}
	knot_wire_set_rcode(pkt->wire, real_rcode);


	bool expiring = false; // TODO
	VERBOSE_MSG(qry, "=> writing RRsets: ");
	for (int i = 0; i < sizeof(ans.rrsets) / sizeof(ans.rrsets[0]); ++i) {
		if (i == 1) knot_pkt_begin(pkt, KNOT_AUTHORITY);
		if (!ans.rrsets[i].set.rr) continue;
		expiring = expiring || ans.rrsets[i].set.expiring;
		ret = pkt_append(pkt, &ans.rrsets[i], ans.rrsets[i].set.rank);
		if (ret) {
			assert(false);
			return ctx->state;
		}
		kr_log_verbose(kr_rank_test(ans.rrsets[i].set.rank, KR_RANK_SECURE)
				? "+" : "-");
	}
	kr_log_verbose("\n");
	/* Finishing touches. */
	qry->flags.EXPIRING = expiring;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	return KR_STATE_DONE;
}


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
static int entry_h_splice(
	knot_db_val_t *val_new_entry, uint8_t rank,
	const knot_db_val_t key, const uint16_t ktype, const uint16_t type,
	const knot_dname_t *owner/*log only*/,
	const struct kr_query *qry, struct kr_cache *cache)
{
	/* Find the whole entry-set and the particular entry within. */
	knot_db_val_t val_orig_all = { }, val_orig_entry = { };
	const struct entry_h *eh_orig = NULL;
	if (!kr_rank_test(rank, KR_RANK_SECURE) || ktype == KNOT_RRTYPE_NS) {
		int ret = cache_op(cache, read, &key, &val_orig_all, 1);
		if (ret) val_orig_all = (knot_db_val_t){ };
		val_orig_entry = val_orig_all;
		switch (entry_h_seek(&val_orig_entry, type)) {
		case 0:
			ret = entry_h_len(val_orig_entry);
			if (ret >= 0) {
				val_orig_entry.len = ret;
				eh_orig = entry_h_consistent(val_orig_entry, type);
				if (eh_orig) {
					break;
				}
			} /* otherwise fall through */
		default:
			val_orig_entry = val_orig_all = (knot_db_val_t){};
		case -ENOENT:
			val_orig_entry.len = 0;
			break;
		};
	}

	if (!kr_rank_test(rank, KR_RANK_SECURE) && eh_orig) {
		/* If equal rank was accepted, spoofing a *single* answer would be
		 * enough to e.g. override NS record in AUTHORITY section.
		 * This way they would have to hit the first answer
		 * (whenever TTL nears expiration). */
		int32_t old_ttl = get_new_ttl(eh_orig, qry->creation_time.tv_sec);
		if (old_ttl > 0 && !is_expiring(old_ttl, eh_orig->ttl)
		    && rank <= eh_orig->rank) {
			WITH_VERBOSE {
				VERBOSE_MSG(qry, "=> not overwriting ");
				kr_rrtype_print(type, "", " ");
				kr_dname_print(owner, "", "\n");
			}
			return kr_error(EEXIST);
		}
	}

	/* Obtain new storage from LMDB.
	 * Note: this does NOT invalidate val_orig_all.data. */
	ssize_t storage_size = val_orig_all.len - val_orig_entry.len
				+ val_new_entry->len;
	assert(storage_size > 0);
	knot_db_val_t val = { .len = storage_size, .data = NULL };
	int ret = cache_op(cache, write, &key, &val, 1);
	if (ret || !val.data || !val.len) {
		assert(ret); /* otherwise "succeeding" but `val` is bad */
		VERBOSE_MSG(qry, "=> failed LMDB write, ret = %d\n", ret);
		return kr_error(ret ? ret : ENOSPC);
	}

	/* Write original data before entry, if any. */
	const ssize_t len_before = val_orig_entry.data - val_orig_all.data;
	assert(len_before >= 0);
	if (len_before) {
		memcpy(val.data, val_orig_all.data, len_before);
	}
	/* Write original data after entry, if any. */
	const ssize_t len_after = val_orig_all.len - val_orig_entry.len;
	assert(len_after >= 0);
	if (len_after) {
		memcpy(val.data + len_before + val_new_entry->len,
			val_orig_entry.data + val_orig_entry.len, len_after);
	}

	val_new_entry->data = val.data + len_before;
	{
		struct entry_h *eh = val_new_entry->data;
		memset(eh, 0, offsetof(struct entry_h, data));
		/* In case (len_before == 0 && ktype == KNOT_RRTYPE_NS) the *eh
		 * set below would be uninitialized and the caller wouldn't be able
		 * to do it after return, as that would overwrite what we do below. */
	}
	/* The multi-entry type needs adjusting the flags. */
	if (ktype == KNOT_RRTYPE_NS) {
		struct entry_h *eh = val.data;
		if (!len_before) {
		}
		if (val_orig_all.len) {
			const struct entry_h *eh0 = val_orig_all.data;
			/* ENTRY_H_FLAGS */
			eh->nsec1_pos = eh0->nsec1_pos;
			eh->nsec3_cnt = eh0->nsec3_cnt;
			eh->has_ns    = eh0->has_ns;
			eh->has_cname = eh0->has_cname;
			eh->has_dname = eh0->has_dname;
		}
		/* we just added/replaced some type */
		switch (type) {
		case KNOT_RRTYPE_NS:
			eh->has_ns = true;  break;
		case KNOT_RRTYPE_CNAME:
			eh->has_cname = true;  break;
		case KNOT_RRTYPE_DNAME:
			eh->has_dname = true;  break;
		default:
			assert(false);
		}
	}
	return kr_ok();
}


static const uint32_t DEFAULT_MAXTTL = 15 * 60,
	DEFAULT_NOTTL = 5; /* Short-time "no data" retention to avoid bursts */

static inline uint32_t limit_ttl(uint32_t ttl)
{
	/* @todo Configurable limit */
	return (ttl > DEFAULT_MAXTTL) ? DEFAULT_MAXTTL : ttl;
}
/** Compute TTL for a packet.  Generally it's minimum TTL, with extra conditions. */
static uint32_t packet_ttl(const knot_pkt_t *pkt, bool is_negative)
{
	bool has_ttl = false;
	uint32_t ttl = UINT32_MAX;
	/* Find minimum entry TTL in the packet or SOA minimum TTL. */
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (is_negative) {
				/* Use SOA minimum TTL for negative answers. */
				if (rr->type == KNOT_RRTYPE_SOA) {
					return limit_ttl(MIN(knot_rrset_ttl(rr), knot_soa_minimum(&rr->rrs)));
				} else {
					continue; /* Use SOA only for negative answers. */
				}
			}
			if (knot_rrtype_is_metatype(rr->type)) {
				continue; /* Skip metatypes. */
			}
			/* Find minimum TTL in the record set */
			knot_rdata_t *rd = rr->rrs.data;
			for (uint16_t j = 0; j < rr->rrs.rr_count; ++j) {
				if (knot_rdata_ttl(rd) < ttl) {
					ttl = limit_ttl(knot_rdata_ttl(rd));
					has_ttl = true;
				}
				rd = kr_rdataset_next(rd);
			}
		}
	}
	/* Get default if no valid TTL present */
	if (!has_ttl) {
		ttl = DEFAULT_NOTTL;
	}
	return limit_ttl(ttl);
}


static int stash_rrset(const ranked_rr_array_t *arr, int arr_i, uint32_t min_ttl,
			const struct kr_query *qry, struct kr_cache *cache);

int cache_lmdb_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	uint16_t pkt_type = knot_pkt_qtype(pkt);
	const bool type_bad = knot_rrtype_is_metatype(pkt_type)
				|| pkt_type == KNOT_RRTYPE_RRSIG;
	/* Note: we cache even in KR_STATE_FAIL.  For example,
	 * BOGUS answer can go to +cd cache even without +cd request. */
	if (!qry || qry->flags.CACHED || type_bad || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Do not cache truncated answers, at least for now.  LATER */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}
	/* Stash individual records. */
	const uint32_t min_ttl = MAX(DEFAULT_MINTTL, req->ctx->cache.ttl_min);
	ranked_rr_array_t *selected[] = kr_request_selected(req);
	int ret = 0;
	for (int psec = KNOT_ANSWER; psec <= KNOT_ADDITIONAL; ++psec) {
		const ranked_rr_array_t *arr = selected[psec];
		/* uncached entries are located at the end */
		for (ssize_t i = arr->len - 1; i >= 0; --i) {
			ranked_rr_array_entry_t *entry = arr->at[i];
			if (entry->qry_uid != qry->uid) {
				continue;
				/* TODO: probably safe to break but maybe not worth it */
			}
			ret = stash_rrset(arr, i, min_ttl, qry, cache);
			if (ret) goto finally;
			/* LATER(optim.): maybe filter out some type-rank combinations
			 * that won't be useful as separate RRsets. */
		}
	}

	/* In some cases, stash also the packet. */
	const bool is_negative = kr_response_classify(pkt)
				& (PKT_NODATA|PKT_NXDOMAIN);
	const bool want_pkt = qry->flags.DNSSEC_BOGUS
		|| (is_negative && qry->flags.DNSSEC_INSECURE);
	if (!want_pkt || !knot_wire_get_aa(pkt->wire)) {
		goto finally;
	}
	
	const uint16_t pkt_size = pkt->size;
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + sizeof(pkt_size) + pkt->size,
	};

	/* Compute rank.  If cd bit is set or we got answer via non-validated
	 * forwarding, make the rank bad; otherwise it depends on flags.
	 * TODO: probably make validator attempt validation even with +cd. */
	uint8_t rank = KR_RANK_AUTH;
	const bool risky_vldr = is_negative && qry->flags.FORWARD && qry->flags.CNAME;
		/* ^^ CNAME'ed NXDOMAIN answer in forwarding mode can contain
		 * unvalidated records; original commit: d6e22f476. */
	if (knot_wire_get_cd(req->answer->wire) || qry->flags.STUB || risky_vldr) {
		kr_rank_set(&rank, KR_RANK_OMIT);
	} else {
		if (qry->flags.DNSSEC_BOGUS) {
			kr_rank_set(&rank, KR_RANK_BOGUS);
		} else if (qry->flags.DNSSEC_INSECURE) {
			kr_rank_set(&rank, KR_RANK_INSECURE);
		} else assert(false);
	}

	const knot_dname_t *owner = knot_pkt_qname(pkt); /* qname can't be compressed */
	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> stashing packet: rank 0%0.2o, ", rank);
		kr_rrtype_print(pkt_type, "", " ");
		kr_dname_print(owner, "", " ");
		kr_log_verbose("(%d B)\n", (int)val_new_entry.len);
	}

	// TODO: nothing exists under NXDOMAIN
#if 0
	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN
	 /* && !qry->flags.DNSSEC_INSECURE */ ) {
		pkt_type = KNOT_RRTYPE_NS;
	}
#endif

	/* Construct the key under which the pkt will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	ret = kr_dname_lf(k->buf, owner, NULL);
	if (ret) {
		assert(!ret);
		goto finally;
	}
	key = key_exact_type_maypkt(k, pkt_type);

	/* Prepare raw memory for the new entry and fill it. */
	ret = entry_h_splice(&val_new_entry, rank, key, k->type, pkt_type,
				owner, qry, cache);
	if (ret) goto finally; /* some aren't really errors */
	assert(val_new_entry.data);
	struct entry_h *eh = val_new_entry.data;
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = packet_ttl(pkt, is_negative);
	eh->rank = rank;
	eh->is_packet = true;
	memcpy(eh->data, &pkt_size, sizeof(pkt_size));
	memcpy(eh->data + sizeof(pkt_size), pkt->wire, pkt_size);

finally:
	kr_cache_sync(cache);
	return ctx->state; /* we ignore cache-stashing errors */
}



/** It's simply inside of cycle taken out to decrease indentation.
 * \return kr_ok() or KR_STATE_FAIL */
static int stash_rrset(const ranked_rr_array_t *arr, int arr_i, uint32_t min_ttl,
			const struct kr_query *qry, struct kr_cache *cache)
{
	const ranked_rr_array_entry_t *entry = arr->at[arr_i];
	if (entry->cached) {
		return kr_ok();
	}
	const knot_rrset_t *rr = entry->rr;
	if (!rr) {
		assert(false);
		return KR_STATE_FAIL;
	}
	if (!check_dname_for_lf(rr->owner)) {
		WITH_VERBOSE {
			VERBOSE_MSG(qry, "=> skipping zero-containing name ");
			kr_dname_print(rr->owner, "", "\n");
		}
		return kr_ok();
	}

	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> considering to stash ");
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(rr->owner, "", "\n");
	}

	switch (rr->type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC3:
		// for now; LATER NSEC3
		return kr_ok();
	default:
		break;
	}

	/* Find corresponding signatures, if validated.  LATER(optim.): speed. */
	const knot_rrset_t *rr_sigs = NULL;
	if (kr_rank_test(entry->rank, KR_RANK_SECURE)) {
		for (ssize_t j = arr->len - 1; j >= 0; --j) {
			/* TODO: ATM we assume that some properties are the same
			 * for all RRSIGs in the set (esp. label count). */
			ranked_rr_array_entry_t *e = arr->at[j];
			bool ok = e->qry_uid == qry->uid && !e->cached
				&& e->rr->type == KNOT_RRTYPE_RRSIG
				&& knot_rrsig_type_covered(&e->rr->rrs, 0) == rr->type
				&& knot_dname_is_equal(rr->owner, e->rr->owner);
			if (!ok) continue;
			bool is_wild = knot_rrsig_labels(&e->rr->rrs, 0)
				!= knot_dname_labels(e->rr->owner, NULL);
			if (is_wild) {
				VERBOSE_MSG(qry, "   2\n");
				return kr_ok(); // FIXME, especially for NSEC1!
			}
			rr_sigs = e->rr;
			break;
		}
	}

	int ret = 0;
	/* Construct the key under which RRs will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	switch (rr->type) {
	case KNOT_RRTYPE_NSEC:
		if (!kr_rank_test(entry->rank, KR_RANK_SECURE)) {
			/* Skip any NSECs that aren't validated. */
			return kr_ok();
		}
		if (!rr_sigs || !rr_sigs->rrs.rr_count || !rr_sigs->rrs.data) {
			assert(false);
			return KR_STATE_FAIL;
		}
		k->zlf_len = knot_dname_size(knot_rrsig_signer_name(&rr_sigs->rrs, 0)) - 1;
		key = key_NSEC1(k, rr->owner, false);
		break;
	default:
		ret = kr_dname_lf(k->buf, rr->owner, NULL);
		if (ret) {
			VERBOSE_MSG(qry, "   3\n");
			return KR_STATE_FAIL;
		}
		key = key_exact_type(k, rr->type);
	}

	/* Compute materialized sizes of the new data. */
	const knot_rdataset_t *rds_sigs = rr_sigs ? &rr_sigs->rrs : NULL;
	const int rr_ssize = rdataset_dematerialize_size(&rr->rrs);
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + rr_ssize
			+ rdataset_dematerialize_size(rds_sigs),
	};

	/* Prepare raw memory for the new entry. */
	ret = entry_h_splice(&val_new_entry, entry->rank, key, k->type, rr->type,
				rr->owner, qry, cache);
	if (ret) return kr_ok(); /* some aren't really errors */
	assert(val_new_entry.data);

	/* Compute TTL, just in case they weren't equal. */
	uint32_t ttl = -1;
	const knot_rdataset_t *rdatasets[] = { &rr->rrs, rds_sigs, NULL };
	for (int j = 0; rdatasets[j]; ++j) {
		knot_rdata_t *rd = rdatasets[j]->data;
		assert(rdatasets[j]->rr_count);
		for (uint16_t l = 0; l < rdatasets[j]->rr_count; ++l) {
			ttl = MIN(ttl, knot_rdata_ttl(rd));
			rd = kr_rdataset_next(rd);
		}
	} /* TODO: consider expirations of RRSIGs as well, just in case. */
	ttl = MAX(ttl, min_ttl);

	/* Write the entry itself. */
	struct entry_h *eh = val_new_entry.data;
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = ttl;
	eh->rank = entry->rank;
	if (rdataset_dematerialize(&rr->rrs, eh->data)
	    || rdataset_dematerialize(rds_sigs, eh->data + rr_ssize)) {
		/* minimize the damage from incomplete write; TODO: better */
		eh->ttl = 0;
		eh->rank = 0;
		assert(false);
	}

	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> stashed rank: 0%0.2o, ", entry->rank);
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(rr->owner, "", " ");
		kr_log_verbose("(%d B total, incl. %d RRSIGs)\n",
				(int)val_new_entry.len,
				(int)(rr_sigs ? rr_sigs->rrs.rr_count : 0)
				);
	}
	return kr_ok();
}


static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* All OK, so start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);

	/* Materialize the sets for the answer in (pseudo-)packet. */
	struct answer ans = {};
	ret = entry2answer(&ans, AR_ANSWER, eh, eh_bound,
			   qry->sname, type, new_ttl);
	CHECK_RET(ret);
	/* Put links to the materialized data into the pkt. */
	ret = pkt_alloc_space(pkt, 1 + (ans.rrsets[AR_ANSWER].sig_rds.rr_count > 0));
	CHECK_RET(ret);
	ret = pkt_append(pkt, &ans.rrsets[AR_ANSWER], eh->rank);
	CHECK_RET(ret);
	/* Finishing touches. */
	qry->flags.EXPIRING = is_expiring(eh->ttl, new_ttl);
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry->flags.DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	if (qry->flags.DNSSEC_INSECURE) {
		qry->flags.DNSSEC_WANT = false;
	}
	return kr_ok();
}
#undef CHECK_RET

static int answer_from_pkt(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	uint16_t pkt_len;
	memcpy(&pkt_len, eh->data, sizeof(pkt_len));
	if (pkt_len > pkt->max_size) {
		return kr_error(ENOENT);
	}

	/* Copy answer and reparse it, but keep the original message id. */
	uint16_t msgid = knot_wire_get_id(pkt->wire);
	knot_pkt_clear(pkt);
	memcpy(pkt->wire, eh->data + 2, pkt_len);
	pkt->size = pkt_len;
	int ret = knot_pkt_parse(pkt, 0);
	if (ret != KNOT_EOK) {
		return kr_error(ret);
	}
	knot_wire_set_id(pkt->wire, msgid);

	/* Rank-related fixups.  Add rank into the additional field. */
	if (kr_rank_test(eh->rank, KR_RANK_INSECURE)) {
		qry->flags.DNSSEC_INSECURE = true;
		qry->flags.DNSSEC_WANT = false;
	}
	for (size_t i = 0; i < pkt->rrset_count; ++i) {
		assert(!pkt->rr[i].additional);
		uint8_t *rr_rank = mm_alloc(&pkt->mm, sizeof(*rr_rank));
		if (!rr_rank) {
			return kr_error(ENOMEM);
		}
		*rr_rank = eh->rank;
		pkt->rr[i].additional = rr_rank;
	}

	/* Adjust TTL in records.  We know that no RR has expired yet. */
	const uint32_t drift = eh->ttl - new_ttl;
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			knot_rdata_t *rd = rr->rrs.data;
			for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
				knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
				rd = kr_rdataset_next(rd);
			}
		}
	}

	/* Finishing touches. TODO: perhaps factor out */
	qry->flags.EXPIRING = is_expiring(eh->ttl, new_ttl);
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry->flags.DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	qry->flags.DNSSEC_BOGUS = kr_rank_test(eh->rank, KR_RANK_BOGUS);
	if (qry->flags.DNSSEC_INSECURE || qry->flags.DNSSEC_BOGUS) {
		qry->flags.DNSSEC_WANT = false;
	}
	return kr_ok();
}

/** TODO: description; see the single call site for now. */
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	int ret = entry_h_seek(&val, qry->stype);
	if (ret) return ret;
	const struct entry_h *eh = entry_h_consistent(val, qry->stype);
	if (!eh) {
		return kr_error(ENOENT);
		// LATER: recovery in case of error, perhaps via removing the entry?
		// LATER(optim): pehaps optimize the zone cut search
	}
	const void *eh_bound = val.data + val.len;

	int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
	if (new_ttl < 0 || eh->rank < lowest_rank) {
		/* Positive record with stale TTL or bad rank.
		 * LATER(optim.): It's unlikely that we find a negative one,
		 * so we might theoretically skip all the cache code. */
		return kr_error(ENOENT);
	}

	if (eh->is_packet) {
		/* Note: we answer here immediately, even if it's (theoretically)
		 * possible that we could generate a higher-security negative proof.
		 * Rank is high-enough so we take it to save time searching. */
		return answer_from_pkt  (ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	} else {
		return answer_simple_hit(ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	}
}

int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{
	struct key k_storage, *k = &k_storage;

	WITH_VERBOSE {
		VERBOSE_MSG(NULL, "_peek_exact: ");
		kr_rrtype_print(type, "", " ");
		kr_dname_print(name, "", " ");
	}

	int ret = kr_dname_lf(k->buf, name, NULL);
	if (ret) {
		kr_log_verbose("ERROR!\n");
		return KR_STATE_FAIL;
	}

	knot_db_val_t key = key_exact_type(k, type);
	knot_db_val_t val = { };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) ret = entry_h_seek(&val, type);
	if (ret) {
		kr_log_verbose("miss (ret: %d)\n", ret);
		return ret;
	}
	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh) {
		kr_log_verbose("miss\n");
		return kr_error(ENOENT);
	}
	*peek = (struct kr_cache_p){
		.time = eh->time,
		.ttl  = eh->ttl,
		.rank = eh->rank,
		.raw_data = val.data,
		.raw_bound = val.data + val.len,
	};
	kr_log_verbose("hit\n");
	return kr_ok();
}

/** Find the longest prefix NS/xNAME (with OK time+rank).
 * We store xNAME at NS type to lower the number of searches.
 * CNAME is only considered for equal name, of course.
 * We also store NSEC* parameters at NS type; probably the latest two will be kept.
 * Found type is returned via k->type.
 *
 * \param exact_match Whether exact match is considered special.
 */
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k)
{
	static const knot_db_val_t NOTHING = {};
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	int zlf_len = k->buf[0];

	// FIXME: review xNAME + DS, ranks, etc.
	uint8_t rank_min = KR_RANK_INSECURE | KR_RANK_AUTH;
	// LATER(optim): if stype is NS, we check the same value again
	bool exact_match = true;
	do {
		k->buf[0] = zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val = { };
		int ret = cache_op(cache, read, &key, &val, 1);
		if (ret == -abs(ENOENT)) goto next_label;
		if (ret) {
			assert(!ret);
			return NOTHING; // TODO: do something with kr_error(ret)?
		}

		/* Check consistency, find any type;
		 * using `goto` for shortening by another label. */
		const struct entry_h *eh = entry_h_consistent(val, KNOT_RRTYPE_NS),
			*eh_orig = eh;
		const knot_db_val_t val_orig = val;
		assert(eh);
		if (!eh) goto next_label; // do something about EILSEQ?
		/* More types are possible; try in order. */
		uint16_t type = 0;
		while (type != KNOT_RRTYPE_DNAME) {
			/* Determine the next type to try. */
			switch (type) {
			case 0:
				type = KNOT_RRTYPE_NS;
				if (!eh_orig->has_ns) continue;
				break;
			case KNOT_RRTYPE_NS:
				type = KNOT_RRTYPE_CNAME;
				/* CNAME is interesting only if we
				 * directly hit the name that was asked */
				if (!exact_match || !eh_orig->has_cname)
					continue;
				break;
			case KNOT_RRTYPE_CNAME:
				type = KNOT_RRTYPE_DNAME;
				/* DNAME is interesting only if we did NOT
				 * directly hit the name that was asked */
				if (exact_match || !eh_orig->has_dname)
					continue;
				break;
			default:
				assert(false);
				return NOTHING;
			}
			/* Find the entry for the type, check positivity, TTL
			 * For non-fatal failures just "continue;" to try the next type. */
			val = val_orig;
			ret = entry_h_seek(&val, type);
			if (ret || !(eh = entry_h_consistent(val, KNOT_RRTYPE_CNAME))) {
				assert(false);
				goto next_label;
			}
			if (eh->is_packet) continue;
			int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
			if (new_ttl < 0) continue;
			if (type != KNOT_RRTYPE_NS && eh->rank < rank_min) {
				continue;
				/* For NS any kr_rank is accepted,
				 * as insecure or even nonauth is OK */
			}
			/* We found our match. */
			k->type = type;
			k->zlf_len = zlf_len;
			return val;
		}

	next_label:
		WITH_VERBOSE {
			VERBOSE_MSG(qry, "NS/xNAME ");
			kr_dname_print(k->zname, "", " NOT found, ");
			kr_log_verbose("name length in LF: %d\n", zlf_len);
		}

		/* remove one more label */
		exact_match = false;
		if (k->zname[0] == 0) { /* missing root NS in cache */
			return NOTHING;
		}
		zlf_len -= (k->zname[0] + 1);
		k->zname += (k->zname[0] + 1);
		k->buf[zlf_len + 1] = 0;
	} while (true);
}


static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry)
{
	const bool allow_unverified = knot_wire_get_cd(req->answer->wire)
					|| qry->flags.STUB;
	/* TODO: move rank handling into the iterator (DNSSEC_* flags)? */
	uint8_t lowest_rank = KR_RANK_INITIAL | KR_RANK_AUTH;
	if (qry->flags.NONAUTH) {
		lowest_rank = KR_RANK_INITIAL;
		/* Note: there's little sense in validation status for non-auth records.
		 * In case of using NONAUTH to get NS IPs, knowing that you ask correct
		 * IP doesn't matter much for security; it matters whether you can
		 * validate the answers from the NS.
		 */
	} else if (!allow_unverified) {
				/* ^^ in stub mode we don't trust RRs anyway */
		/* Records not present under any TA don't have their security
		 * verified at all, so we also accept low ranks in that case. */
		const bool ta_covers = kr_ta_covers_qry(req->ctx, qry->sname, qry->stype);
		/* ^ TODO: performance?  TODO: stype - call sites */
		if (ta_covers) {
			kr_rank_set(&lowest_rank, KR_RANK_INSECURE);
		}
	}
	return lowest_rank;
}




