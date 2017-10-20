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

/**
 * @internal Composed key as { u8 tag, u8[1-255] name, u16 type }
 * The name is lowercased and label order is reverted for easy prefix search.
 * e.g. '\x03nic\x02cz\x00' is saved as '\0x00cz\x00nic\x00'
 */
static size_t cache_key(uint8_t *buf, uint8_t tag, const knot_dname_t *name, uint16_t rrtype)
{
	/* Convert to lookup format */
	int ret = kr_dname_lf(buf, name, NULL);
	if (ret != 0) {
		return 0;
	}
	/* Write tag + type */
	uint8_t name_len = buf[0];
	buf[0] = tag;
	memcpy(buf + sizeof(uint8_t) + name_len, &rrtype, sizeof(uint16_t));
	return name_len + KEY_HSIZE;
}

static struct kr_cache_entry *lookup(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	if (!name || !cache) {
		return NULL;
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);

	/* Look up and return value */
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret != 0) {
		return NULL;
	}

	return (struct kr_cache_entry *)val.data;
}

static int check_lifetime(struct kr_cache_entry *found, uint32_t *timestamp)
{
	/* No time constraint */
	if (!timestamp) {
		return kr_ok();
	} else if (*timestamp <= found->timestamp) {
		/* John Connor record cached in the future. */
		*timestamp = 0;
		return kr_ok();
	} else {
		/* Check if the record is still valid. */
		uint32_t drift = *timestamp - found->timestamp;
		if (drift <= found->ttl) {
			*timestamp = drift;
			return kr_ok();
		}
	}
	return kr_error(ESTALE);
}

int kr_cache_peek(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type,
                  struct kr_cache_entry **entry, uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !name || !entry) {
		return kr_error(EINVAL);
	}

	struct kr_cache_entry *found = lookup(cache, tag, name, type);
	if (!found) {
		cache->stats.miss += 1;
		return kr_error(ENOENT);
	}

	/* Check entry lifetime */
	*entry = found;
	int ret = check_lifetime(found, timestamp);
	if (ret == 0) {
		cache->stats.hit += 1;
	} else {
		cache->stats.miss += 1;
	}
	return ret;
}

static void entry_write(struct kr_cache_entry *dst, struct kr_cache_entry *header, knot_db_val_t data)
{
	memcpy(dst, header, sizeof(*header));
	if (data.data)
		memcpy(dst->data, data.data, data.len);
}

int kr_cache_insert(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type,
                    struct kr_cache_entry *header, knot_db_val_t data)
{
	if (!cache_isvalid(cache) || !name || !header) {
		return kr_error(EINVAL);
	}

	/* Enforce cache maximum TTL limits without TTL decay.
	 * Minimum TTL is enforced in specific caches as it requires
	 * rewriting of the records to avoid negative TTL when decayed. */
	header->ttl = MIN(header->ttl, cache->ttl_max);

	/* Prepare key/value for insertion. */
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	assert(data.len != 0);
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t entry = { NULL, sizeof(*header) + data.len };

	/* LMDB can do late write and avoid copy */
	int ret = 0;
	cache->stats.insert += 1;
	if (cache->api == kr_cdb_lmdb()) {
		ret = cache_op(cache, write, &key, &entry, 1);
		if (ret != 0) {
			return ret;
		}
		entry_write(entry.data, header, data);
	} else {
		/* Other backends must prepare contiguous data first */
		auto_free char *buffer = malloc(entry.len);
		entry.data = buffer;
		entry_write(entry.data, header, data);
		ret = cache_op(cache, write, &key, &entry, 1);
	}

	return ret;
}

int kr_cache_remove(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	knot_db_val_t key = { keybuf, key_len };
	cache->stats.delete += 1;
	return cache_op(cache, remove, &key, 1);
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

int kr_cache_match(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, knot_db_val_t *val, int maxcount)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}
	if (!cache->api->match) {
		return kr_error(ENOSYS);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, 0);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}

	/* Trim type from the search key */ 
	knot_db_val_t key = { keybuf, key_len - 2 };
	return cache_op(cache, match, &key, val, maxcount);
}

int kr_cache_peek_rr(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank, uint8_t *flags, uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !rr || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(cache, KR_CACHE_RR, rr->owner, rr->type, &entry, timestamp);
	if (ret != 0) {
		return ret;
	}
	if (rank) {
		*rank = entry->rank;
	}
	if (flags) {
		*flags = entry->flags;
	}
	rr->rrs.rr_count = entry->count;
	rr->rrs.data = entry->data;
	return kr_ok();
}

int kr_cache_peek_rank(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type, uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !name) {
		return kr_error(EINVAL);
	}
	struct kr_cache_entry *found = lookup(cache, tag, name, type);
	if (!found) {
		return kr_error(ENOENT);
	}
	if (check_lifetime(found, &timestamp) != 0) {
		return kr_error(ESTALE);
	}
	return found->rank;
}

int kr_cache_materialize_x(knot_rrset_t *dst, const knot_rrset_t *src, uint32_t drift,
		uint reorder, knot_mm_t *mm)
{
	if (!dst || !src || dst == src) {
		return kr_error(EINVAL);
	}

	/* Make RRSet copy */
	knot_rrset_init(dst, NULL, src->type, src->rclass);
	dst->owner = knot_dname_copy(src->owner, mm);
	if (!dst->owner) {
		return kr_error(ENOMEM);
	}

	/* Find valid records */
	knot_rdata_t **valid = malloc(sizeof(knot_rdata_t *) * src->rrs.rr_count);
	uint16_t valid_count = 0;
	knot_rdata_t *rd = src->rrs.data;
	for (uint16_t i = 0; i < src->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) >= drift) {
			valid[valid_count++] = rd;
		}
		rd = kr_rdataset_next(rd);
	}

	if (reorder && valid_count > 1) {
		/* Reorder the valid part; it's a reversed rotation,
		 * done by two array reversals. */
		uint16_t shift = reorder % valid_count;
		for (uint16_t i = 0; i < shift / 2; ++i) {
			SWAP(valid[i], valid[shift - 1 - i]);
		}
		for (uint16_t i = 0; i < (valid_count - shift) / 2; ++i) {
			SWAP(valid[shift + i], valid[valid_count - 1 - i]);
		}
	}

	int err = knot_rdataset_gather(&dst->rrs, valid, valid_count, mm);
	free(valid);
	if (err) {
		knot_rrset_clear(dst, mm);
		return kr_error(err);
	}

	/* Fixup TTL by time passed */
	rd = dst->rrs.data;
	for (uint16_t i = 0; i < dst->rrs.rr_count; ++i) {
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
		rd = kr_rdataset_next(rd);
	}

	return kr_ok();
}

int kr_cache_insert_rr(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare header to write */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = 0,
		.rank = rank,
		.flags = flags,
		.count = rr->rrs.rr_count
	};
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) > header.ttl) {
			header.ttl = knot_rdata_ttl(rd);
		}
		rd = kr_rdataset_next(rd);
	}

	knot_db_val_t data = { rr->rrs.data, knot_rdataset_size(&rr->rrs) };
	return kr_cache_insert(cache, KR_CACHE_RR, rr->owner, rr->type, &header, data);
}

int kr_cache_peek_rrsig(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank, uint8_t *flags, uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !rr || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(cache, KR_CACHE_SIG, rr->owner, rr->type, &entry, timestamp);
	if (ret != 0) {
		return ret;
	}
	assert(entry);
	if (rank) {
		*rank = entry->rank;
	}
	if (flags) {
		*flags = entry->flags;
	}
	rr->type = KNOT_RRTYPE_RRSIG;
	rr->rrs.rr_count = entry->count;
	rr->rrs.data = entry->data;
	return kr_ok();
}

int kr_cache_insert_rrsig(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare header to write */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = 0,
		.rank = rank,
		.flags = flags,
		.count = rr->rrs.rr_count
	};
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdata_ttl(rd) > header.ttl) {
			header.ttl = knot_rdata_ttl(rd);
		}
	}

	uint16_t covered = knot_rrsig_type_covered(&rr->rrs, 0);
	knot_db_val_t data = { rr->rrs.data, knot_rdataset_size(&rr->rrs) };
	return kr_cache_insert(cache, KR_CACHE_SIG, rr->owner, covered, &header, data);
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
 *		FIXME: NSEC3 chain descriptors (iff nsec3_cnt > 0)
 *	- is_negative: uint16_t length, otherwise opaque ATM;
 *	- otherwise RRset + its RRSIG set (possibly empty).
 * */
struct entry_h {
	uint32_t time;	/**< The time of inception. */
	uint32_t ttl;	/**< TTL at inception moment.  Assuming it fits into int32_t ATM. */
	uint8_t  rank;	/**< See enum kr_rank */

	bool is_negative : 1;	/**< Negative-answer packet for insecure/bogus name. */

	unsigned nsec1_pos : 2;	/**< Only used for NS ktype. */
	unsigned nsec3_cnt : 2;	/**< Only used for NS ktype. */
	bool has_ns : 1;	/**< Only used for NS ktype. */
	bool has_cname : 1;	/**< Only used for NS ktype. */
	bool has_dname : 1;	/**< Only used for NS ktype. */

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
	if (data.len < offsetof(struct entry_h, data))
		return NULL;
	const struct entry_h *eh = data.data;
	bool ok = true;

	switch (ktype) {
	case KNOT_RRTYPE_NSEC:
		ok = ok && !(eh->is_negative || eh->has_ns || eh->has_cname
				|| eh->has_dname);
		break;
	default:
		if (eh->is_negative)
			ok = ok && !kr_rank_test(eh->rank, KR_RANK_SECURE);
	}

	//LATER: rank sanity
	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}


struct key {
	const knot_dname_t *dname; /**< corresponding dname (points within qry->sname) */
	uint16_t type; /**< corresponding type */
	uint8_t name_len; /**< current length of the name in buf */
	uint8_t buf[KR_CACHE_KEY_MAXLEN];
};



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
			   uint8_t lowest_rank, uint16_t ktype);
static const struct entry_h *closest_NS(kr_layer_t *ctx, struct key *k);




struct answer {
	int rcode;	/**< PKT_NODATA, etc. ?? */
	uint8_t nsec_v;	/**< 1 or 3 */
	knot_mm_t *mm;	/**< Allocator for rrsets */
	struct answer_rrset {
		ranked_rr_array_entry_t set;	/**< set+rank for the main data */
		knot_rdataset_t sig_rds;	/**< RRSIG data, if any */
	} rrsets[1+1+3]; /**< answer, SOA, 3*NSECx (at most, all optional) */
};
enum {
	AR_ANSWER = 0,
	AR_SOA,
	AR_NSEC,
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

/** Given a valid entry header, find the next one (and check it).
 * \note It's const-polymorphic, really. */
static struct entry_h *entry_h_next(struct entry_h *eh, const void *data_bound)
{
	assert(eh && data_bound);
	void *d = eh->data; /* iterates over the cache data */
	if (d >= data_bound) return NULL;
	if (!eh->is_negative) { /* Positive RRset + its RRsig set (may be empty). */
		int sets = 2;
		while (sets-- > 0) {
			if (d + 1 > data_bound) return NULL;
			uint8_t rr_count;
			memcpy(&rr_count, d++, sizeof(rr_count));
			for (int i = 0; i < rr_count; ++i) {
				if (d + 2 > data_bound) return NULL;
				uint16_t len;
				memcpy(&len, d, sizeof(len));
				d += 2 + len;
			}
		}
	} else { /* A "packet" (opaque ATM). */
		if (d + 2 > data_bound) return NULL;
		uint16_t len;
		memcpy(&len, d, sizeof(len));
		d += 2 + len;
	}
	if (d > data_bound) return NULL;
	knot_db_val_t val = { .data = d, .len = data_bound - d };
	return entry_h_consistent(val, KNOT_RRTYPE_NS);
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
	for (int i = 0; i < 2; ++i) {
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







/** TODO */
static knot_db_val_t key_exact_type(struct key *k, uint16_t ktype)
{
	k->buf[k->name_len + 1] = 0; /* make sure different names can never match */
	k->buf[k->name_len + 2] = 'E'; /* tag for exact name+type matches */
	memcpy(k->buf + k->name_len + 3, &ktype, 2);
	k->type = ktype;
	/* CACHE_KEY_DEF: key == dname_lf + '\0' + 'E' + RRTYPE */
	return (knot_db_val_t){ k->buf + 1, k->name_len + 4 };
}

/** TODO */
static knot_db_val_t key_NSEC1(struct key *k, const knot_dname_t *name, int zonename_len)
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

	VERBOSE_MSG(NULL, "<> key_NSEC1; ");
	kr_dname_print(name, "name: ", " ");
	kr_log_verbose("(zone name LF length: %d)\n", zonename_len);

	uint8_t *begin = k->buf + 1 + zonename_len; /* one byte after zone's zero */
	uint8_t *end = k->buf + 1 + k->buf[0]; /* we don't use the final zero in key,
						* but move it anyway */
	if (end < begin) {
		assert(false);
		return (knot_db_val_t){};
	}
	if (end > begin)
		memmove(begin + 2, begin, end - begin);
	begin[0] = 0;
	begin[1] = '1'; /* tag for NSEC1 */
	/* CACHE_KEY_DEF: key == zone's dname_lf + 0 + '1' + dname_lf
	 * of the name within the zone without the final 0 */
	return (knot_db_val_t){ k->buf + 1, k->buf[0] + 1 };
}



/** function for .produce phase */
int cache_lmdb_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || (qry->flags.NO_CACHE)
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state; /* Already resolved/failed or already tried, etc. */
	}
	/* ATM cache only peeks for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * TODO Note: it's important to skip this if rrcache sets KR_STATE_DONE,
	 * as CNAME chains need more iterations to get fetched. */
	qry->flags.NO_CACHE = true;


	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, qry->sname, NULL);
	if (ret) {
		return KR_STATE_FAIL;
	}
	k->name_len = k->buf[0];

	const uint8_t lowest_rank = get_lowest_rank(req, qry);
	// FIXME: the whole approach to +cd answers

	/** 1. find the name or the closest (available) zone, not considering wildcards
	 *  1a. exact name+type match (can be negative answer in insecure zones)
	 */
	uint16_t ktype = qry->stype;
	if (ktype == KNOT_RRTYPE_CNAME || ktype == KNOT_RRTYPE_DNAME) {
		ktype = KNOT_RRTYPE_NS;
	}
	knot_db_val_t key = key_exact_type(k, ktype);
	knot_db_val_t val = { };
	ret = cache_op(cache, read, &key, &val, 1);
	switch (ret) {
	case 0: /* found an entry: test conditions, materialize into pkt, etc. */
		ret = found_exact_hit(ctx, pkt, val, lowest_rank, ktype);
		if (ret == -abs(ENOENT)) {
			break;
		} else if (ret) {
			VERBOSE_MSG(qry, "=> exact hit but error: %d %s\n",
					ret, strerror(abs(ret)));
			return ctx->state;
		}
		VERBOSE_MSG(qry, "=> satisfied from cache (direct positive hit)\n");
		return KR_STATE_DONE;
	case (-abs(ENOENT)):
		break;
	default:
		assert(false);
		return ctx->state;
	}


	/** 1b. otherwise, find the longest prefix NS/xNAME (with OK time+rank). [...] */
	k->dname = qry->sname;
	kr_dname_lf(k->buf, qry->sname, NULL); /* LATER(optim.): probably remove */
	k->name_len = k->buf[0];
	const struct entry_h *eh = closest_NS(ctx, k);
	if (!eh) {
		VERBOSE_MSG(qry, "=> not even root NS in cache\n");
		return ctx->state; /* nothing to do without any NS at all */
	}
	VERBOSE_MSG(qry, "=> trying zone: ");
	kr_dname_print(k->dname, "", "\n");
#if 0
	if (!eh) { /* fall back to root hints? */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret) return KR_STATE_FAIL;
		assert(!qry->zone_cut.parent);

		//VERBOSE_MSG(qry, "=> using root hints\n");
		//qry->flags.AWAIT_CUT = false;
		return ctx->state;
	}
#endif
	switch (k->type) {
	// FIXME xNAME: return/generate whatever is required
	case KNOT_RRTYPE_NS:
		break;
	default:
		assert(false);
		return ctx->state;
	}

#if 0
	/* Now `eh` points to the closest NS record that we've found,
	 * and that's the only place to start - we may either find
	 * a negative proof or we may query upstream from that point. */
	kr_zonecut_set(&qry->zone_cut, k->dname);
	ret = kr_make_query(qry, pkt); // FIXME: probably not yet - qname minimization
	if (ret) return KR_STATE_FAIL;
#endif


	/* Note: up to here we can run on any cache backend,
	 * without touching the code. */

	if (!eh->nsec1_pos) {
		/* No NSEC1 RRs for this zone in cache. */
		/* TODO: NSEC3 */
		//VERBOSE_MSG(qry, "   no NSEC1\n");
		//return ctx->state;
	}

	/* collecting multiple NSEC* + RRSIG records, in preparation for the answer
	 *  + track the progress
	 */
	struct answer ans = {};
	ans.mm = &pkt->mm;

	/** 2. closest (provable) encloser.
	 * iterate over all NSEC* chain parameters
	 */
	//while (true) { //for (int i_nsecp = 0; i
		assert(eh->nsec1_pos <= 1);
		int nsec = 1;
		switch (nsec) {
		case 1: {
 			/* find a previous-or-equal name+NSEC in cache covering
			 * the QNAME, checking TTL etc. */
			
			ans.nsec_v = 1;
			//nsec_leq()
			const int zname_lf_len = k->name_len; /* zone name lf length */
			knot_db_val_t key = key_NSEC1(k, qry->sname, zname_lf_len);
			const int sname_lf_len = k->buf[0];
			if (!key.data) break; /* FIXME: continue?
				similarly: other breaks here - also invalidate ans AR_NSEC */
			knot_db_val_t val = { };
			ret = cache_op(cache, read_leq, &key, &val);
			if (ret < 0) {
				VERBOSE_MSG(qry, "=> NSEC: range search miss\n");
				break;
			}
			bool exact_match = (ret == 0);
			const struct entry_h *eh = entry_h_consistent(val, KNOT_RRTYPE_NSEC);
			void *eh_data_bound = val.data + val.len;
			if (!eh) break;
			int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
			if (new_ttl < 0 || !kr_rank_test(eh->rank, KR_RANK_SECURE)) {
				VERBOSE_MSG(qry, "=> NSEC: range search found stale entry\n");
				// TODO: remove the stale record *and* retry
				break;
			}

			knot_dname_t dname_buf[KNOT_DNAME_MAXLEN];
			size_t nwz_off = zname_lf_len + 2;
				/* CACHE_KEY_DEF: zone name lf + 0 '1' + name within zone */

			if (!exact_match) {
				/* The NSEC starts strictly before our target name;
				 * check that it's still within the zone and that
				 * it ends strictly after the sought name
				 * (or points to origin). */
				bool in_zone = key.len >= nwz_off
					/* CACHE_KEY_DEF */
					&& memcmp(k->buf + 1, key.data, nwz_off) == 0;
				if (!in_zone) {
					VERBOSE_MSG(qry, "=> NSEC: range search miss (!in_zone)\n");
					break;
				}
				const knot_dname_t *next = eh->data + 3; /* it's *full* name ATM */
				if (!eh->data[0]) {
					assert(false);
					break;
					/* TODO: more checks?  Also, `data + 3` is kinda messy. */
				}
				WITH_VERBOSE {
					VERBOSE_MSG(qry, "=> NSEC: next name: ");
					kr_dname_print(next, "", "\n");
				}
				uint8_t *next_lf = dname_buf;
				ret = kr_dname_lf(next_lf, next, NULL);
				if (ret) break;
				int next_nwz_len = next_lf[0] - zname_lf_len;
				next_lf += 1 + zname_lf_len; /* skip the zone name */
				assert(next_nwz_len >= 0);
				bool covers = next_nwz_len == 0
					/* CACHE_KEY_DEF */
					|| memcmp(k->buf + 1 + nwz_off, next_lf,
						  MIN(sname_lf_len - zname_lf_len, next_nwz_len)
						) < 0;
				if (!covers) {
					VERBOSE_MSG(qry, "=> NSEC: range search miss (!covers)\n");
					break;
				}
			}

			/* Get owner name of the record. */
			const knot_dname_t *owner;
			if (exact_match) {
				owner = qry->sname;
			} else {
				/* Reconstruct from key: first the ending, then zone name. */
				ret = knot_dname_lf2wire(dname_buf, key.len - nwz_off,
							 key.data + nwz_off);
					/* CACHE_KEY_DEF */
				if (ret) break;
				ret = knot_dname_to_wire(dname_buf + (key.len - nwz_off), k->dname,
								/* TODO: messy zone name ^^ */
						   KNOT_DNAME_MAXLEN - (key.len-nwz_off));
				if (ret != zname_lf_len + 1) {
					assert(false);
					break;
				}
				owner = dname_buf;
			}
			VERBOSE_MSG(qry, "=> NSEC: LF2wire OK\n");

			/* Basic checks OK -> materialize data. */
			ret = entry2answer(&ans, AR_NSEC, eh, eh_data_bound,
					   owner, KNOT_RRTYPE_NSEC, new_ttl);
			if (ret) break;
			VERBOSE_MSG(qry, "=> NSEC: materialized OK\n");

			if (exact_match) {
				uint8_t *bm = NULL;
				uint16_t bm_size;
				knot_nsec_bitmap(&ans.rrsets[AR_NSEC].set.rr->rrs,
						 &bm, &bm_size);
				if (!bm || kr_nsec_bitmap_contains_type(bm, bm_size, qry->stype)) {
					//FIXME: clear the answer?
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
				break;
			}

			}
		case 3: //TODO NSEC3
		default:
			assert(false);
		}
	//}

	/** 3. wildcard checks.  FIXME
	 */
	if (ans.nsec_v == 1 && ans.rcode == PKT_NODATA) {
		// no wildcard checks needed
	}

	/** 4. add SOA iff needed
	 */
	if (ans.rcode != PKT_NOERROR) {
		/* assuming k->buf still starts with zone's prefix */
		key = key_exact_type(k, KNOT_RRTYPE_SOA);
		knot_db_val_t val = { };
		ret = cache_op(cache, read, &key, &val, 1);
		const struct entry_h *eh;
		if (ret || !(eh = entry_h_consistent(val, ktype))) {
			return ctx->state;
		}
		void *eh_data_bound = val.data + val.len;

		int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_negative) {
			return ctx->state;
		}
		ret = entry2answer(&ans, AR_SOA, eh, eh_data_bound,
				   k->dname, KNOT_RRTYPE_SOA, new_ttl);
		if (ret) return ctx->state;
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


static int stash_rrset(const ranked_rr_array_t *arr, int arr_i, uint32_t min_ttl,
			const struct kr_query *qry, struct kr_cache *cache);

int cache_lmdb_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	if (!qry || ctx->state & KR_STATE_FAIL || qry->flags.CACHED) {
		return ctx->state;
	}
	/* Do not cache truncated answers, at least for now.  LATER */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}

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
			int ret = stash_rrset(arr, i, min_ttl, qry, cache);
			if (ret) goto finally;
		}
	}
finally:
	kr_cache_sync(cache);
	return ret ? ret : ctx->state;
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
	knot_rrset_t *rr = entry->rr;
	if (!rr) {
		assert(false);
		return KR_STATE_FAIL;
	}


	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> considering to stash ");
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(rr->owner, "", "\n");
	}

	switch (rr->type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC3:
		// for now; FIXME
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
			if (e->qry_uid != qry->uid || e->cached
			    || e->rr->type != KNOT_RRTYPE_RRSIG
			    || knot_rrsig_type_covered(&e->rr->rrs, 0) != rr->type
			    || !knot_dname_is_equal(rr->owner, e->rr->owner))
			{
				continue;
			}
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
	uint16_t ktype = rr->type;
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	switch (ktype) {
	case KNOT_RRTYPE_NSEC:
		if (!rr_sigs || !rr_sigs->rrs.rr_count || !rr_sigs->rrs.data) {
			assert(false);
			return KR_STATE_FAIL;
		}
		const int zone_lf_len = knot_dname_size(
			knot_rrsig_signer_name(&rr_sigs->rrs, 0)) - 1;
		key = key_NSEC1(k, rr->owner, zone_lf_len);
		break;
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		assert(false); // FIXME NOTIMPL ATM
		ktype = KNOT_RRTYPE_NS; // fallthrough
	default:
		ret = kr_dname_lf(k->buf, rr->owner, NULL);
		if (ret) {
			VERBOSE_MSG(qry, "   3\n");
			return KR_STATE_FAIL;
		}
		k->name_len = k->buf[0];

		key = key_exact_type(k, ktype);
	}

	if (!kr_rank_test(entry->rank, KR_RANK_SECURE)) {
		/* If equal rank was accepted, spoofing a single answer would be enough
		 * to e.g. override NS record in AUTHORITY section.
		 * This way they would have to hit the first answer
		 * (whenever TTL nears expiration). */
		knot_db_val_t val = { };
		ret = cache_op(cache, read, &key, &val, 1);
		struct entry_h *eh;
		if (ret == 0 && (eh = entry_h_consistent(val, ktype))) {
			int32_t old_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
			if (old_ttl > 0 && !is_expiring(old_ttl, eh->ttl)
			    && entry->rank <= eh->rank) {
				WITH_VERBOSE {
					VERBOSE_MSG(qry, "=> not overwriting ");
					kr_rrtype_print(rr->type, "", " ");
					kr_dname_print(rr->owner, "", "\n");
				}
				return kr_ok();
			}
		}
	}

	const knot_rdataset_t *rds_sigs = rr_sigs ? &rr_sigs->rrs : NULL;
	/* Compute TTL, just in case they weren't equal. */
	uint32_t ttl = -1;
	const knot_rdataset_t *rdatasets[] = { &rr->rrs, rds_sigs, NULL };
	for (int j = 0; rdatasets[j]; ++j) {
		knot_rdata_t *rd = rdatasets[j]->data;
		for (uint16_t l = 0; l < rdatasets[j]->rr_count; ++l) {
			ttl = MIN(ttl, knot_rdata_ttl(rd));
			rd = kr_rdataset_next(rd);
		}
	} /* TODO: consider expirations of RRSIGs as well, just in case. */
	ttl = MAX(ttl, min_ttl);

	int rr_ssize = rdataset_dematerialize_size(&rr->rrs);
	int storage_size = offsetof(struct entry_h, data) + rr_ssize
		+ rdataset_dematerialize_size(rds_sigs);

	knot_db_val_t val = { .len = storage_size, .data = NULL };
	ret = cache_op(cache, write, &key, &val, 1);
	if (ret) return kr_ok();
	struct entry_h *eh = val.data;
	*eh = (struct entry_h){
		.time = qry->timestamp.tv_sec,
		.ttl  = ttl,
		.rank = entry->rank,
		.has_ns = rr->type == KNOT_RRTYPE_NS,
	};
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
		kr_log_verbose("(%d B)\n", (int)storage_size);
	}
	return kr_ok();
}


/** FIXME: description; see the single call site for now. */
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank, uint16_t ktype)
{
#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)

	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	const struct entry_h *eh = entry_h_consistent(val, ktype);
	if (!eh) {
		CHECK_RET(-EILSEQ);
		// LATER: recovery, perhaps via removing the entry?
	}
	void *eh_data_bound = val.data + val.len;

	/* In case of NS ktype, there may be multiple types within.
	 * Find the one we want. */
	if (ktype == KNOT_RRTYPE_NS) {
		bool present;
		switch (qry->stype) {
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
			CHECK_RET(-EINVAL);
		}
		if (!present) {
			return kr_error(ENOENT);
			// LATER(optim): pehaps optimize the zone cut search
		}
		/* we may need to skip some RRset in eh_data */
		int sets_to_skip = 0;
		switch (qry->stype) {
		case KNOT_RRTYPE_DNAME:
			sets_to_skip += eh->has_cname;
		case KNOT_RRTYPE_CNAME:
			sets_to_skip += eh->has_ns;
		case KNOT_RRTYPE_NS:
			break;
		}
		while (sets_to_skip-- > 0) {
			eh = entry_h_next(/*const-cast*/(struct entry_h *)eh, eh_data_bound);
			if (!eh) CHECK_RET(-EILSEQ);
			// LATER: recovery, perhaps via removing the entry?
		}
	}

	int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
	if (new_ttl < 0 || eh->rank < lowest_rank) {
		/* Positive record with stale TTL or bad rank.
		 * It's unlikely that we find a negative one,
		 * so we might theoretically skip all the cache code. */
		return kr_error(ENOENT);
	}

	if (eh->is_negative) {
		// insecure zones might have a negative-answer packet here
		//FIXME
		assert(false);
	}

	/* All OK, so start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);

	/* Materialize the sets for the answer in (pseudo-)packet. */
	struct answer ans = {};
	ret = entry2answer(&ans, AR_ANSWER, eh, eh_data_bound,
			   qry->sname, qry->stype, new_ttl);
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
	return kr_ok();
#undef CHECK_RET
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
	k->name_len = k->buf[0];

	uint16_t ktype = type;
	if (ktype == KNOT_RRTYPE_CNAME || ktype == KNOT_RRTYPE_DNAME) {
		assert(false); // FIXME NOTIMPL ATM
		ktype = KNOT_RRTYPE_NS;
	}
	knot_db_val_t key = key_exact_type(k, ktype);
	knot_db_val_t val = { };
	ret = cache_op(cache, read, &key, &val, 1);
	if (ret) {
		kr_log_verbose("miss\n");
		return ret;
	}
	const struct entry_h *eh = entry_h_consistent(val, ktype);
	if (!eh || (type == KNOT_RRTYPE_NS && !eh->has_ns)) {
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
 */
static const struct entry_h *closest_NS(kr_layer_t *ctx, struct key *k)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	// FIXME: DS is parent-side record
	bool exact_match = true;
	// LATER(optim): if stype is NS, we check the same value again
	do {
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val = { };
		int ret = cache_op(cache, read, &key, &val, 1);
		switch (ret) {
		case 0: {
			const struct entry_h *eh = entry_h_consistent(val, KNOT_RRTYPE_NS);
			assert(eh);
			if (!eh) break; // do something about EILSEQ?
			int32_t new_ttl = get_new_ttl(eh, qry->creation_time.tv_sec);
			if (new_ttl < 0) break;
			// FIXME: xNAME
			//uint16_t ktype = exact_match ? KNOT_RRTYPE_CNAME : KNOT_RRTYPE_DNAME;
			if (!eh->has_ns || eh->is_negative) {
				break;
			}
			/* any kr_rank is accepted, as insecure or even nonauth is OK */
			k->type = KNOT_RRTYPE_NS;
			return eh;
			}
		case (-abs(ENOENT)):
			break;
		default:
			assert(false);
			return NULL; // TODO: do something with kr_error(ret)?
		}

		WITH_VERBOSE {
			VERBOSE_MSG(qry, "NS ");
			kr_dname_print(k->dname, "", " NOT found, ");
			kr_log_verbose("name length in LF: %d\n", k->name_len);
		}

		/* remove one more label */
		exact_match = false;
		if (k->dname[0] == 0) { /* missing root NS in cache */
			return NULL;
		}
		k->name_len -= (k->dname[0] + 1);
		k->dname += (k->dname[0] + 1);
		k->buf[k->name_len + 1] = 0;
	} while (true);
}


static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry)
{
	const bool allow_unverified = knot_wire_get_cd(req->answer->wire)
					|| qry->flags.STUB;
	/* TODO: move rank handling into the iterator (DNSSEC_* flags)? */
	uint8_t rank  = 0;
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




