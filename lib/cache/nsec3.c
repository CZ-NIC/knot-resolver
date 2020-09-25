/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Implementation of NSEC3 handling.  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"

#include "contrib/base32hex.h"
#include "lib/dnssec/nsec.h"
#include "lib/layer/iterate.h"

#include <libknot/rrtype/nsec3.h>

static const knot_db_val_t VAL_EMPTY = { NULL, 0 };

/** Common part: write all but the NSEC3 hash. */
static knot_db_val_t key_NSEC3_common(struct key *k, const knot_dname_t *zname,
					const nsec_p_hash_t nsec_p_hash)
{
	int ret;
	const bool ok = k && zname
		&& !(ret = kr_dname_lf(k->buf, zname, false));
	if (!ok) {
		assert(false);
		return VAL_EMPTY;
	}

	/* CACHE_KEY_DEF: key == zone's dname_lf + '\0' + '3' + nsec_p hash (4B)
	 * 			+ NSEC3 hash (20B == NSEC3_HASH_LEN binary!)
	 * LATER(optim.) nsec_p hash: perhaps 2B would give a sufficient probability
	 * of avoiding collisions.
	 */
	uint8_t *begin = k->buf + 1 + k->zlf_len; /* one byte after zone's zero */
	begin[0] = 0;
	begin[1] = '3'; /* tag for NSEC3 */
	k->type = KNOT_RRTYPE_NSEC3;
	memcpy(begin + 2, &nsec_p_hash, sizeof(nsec_p_hash));
	return (knot_db_val_t){
		.data = k->buf + 1,
		.len = begin + 2 + sizeof(nsec_p_hash) - (k->buf + 1),
	};
}

knot_db_val_t key_NSEC3(struct key *k, const knot_dname_t *nsec3_name,
			const nsec_p_hash_t nsec_p_hash)
{
	knot_db_val_t val = key_NSEC3_common(k, nsec3_name /*only zname required*/,
						nsec_p_hash);
	if (!val.data) return val;
	int len = base32hex_decode(nsec3_name + 1, nsec3_name[0],
			knot_db_val_bound(val), KR_CACHE_KEY_MAXLEN - val.len);
	if (len != NSEC3_HASH_LEN) {
		return VAL_EMPTY;
	}
	val.len += len;
	return val;
}

/** Construct a string key for for NSEC3 predecessor-search, from an non-NSEC3 name.
 * \note k->zlf_len and k->zname are assumed to have been correctly set */
static knot_db_val_t key_NSEC3_name(struct key *k, const knot_dname_t *name,
		const bool add_wildcard, const struct nsec_p *nsec_p)
{
	bool ok = k && name && nsec_p && nsec_p->raw;
	if (!ok) return VAL_EMPTY;
	knot_db_val_t val = key_NSEC3_common(k, k->zname, nsec_p->hash);
	if (!val.data) return val;

	/* Make `name` point to correctly wildcarded owner name. */
	uint8_t buf[KNOT_DNAME_MAXLEN];
	int name_len;
	if (add_wildcard) {
		buf[0] = '\1';
		buf[1] = '*';
		name_len = knot_dname_to_wire(buf + 2, name, sizeof(buf) - 2);
		if (name_len < 0) return VAL_EMPTY; /* wants wildcard but doesn't fit */
		name = buf;
		name_len += 2;
	} else {
		name_len = knot_dname_size(name);
	}
	/* Append the NSEC3 hash. */
	const dnssec_binary_t dname = {
		.size = name_len,
		.data = (uint8_t *)/*const-cast*/name,
	};

	#if 0 // LATER(optim.): this requires a patched libdnssec - tries to realloc()
	dnssec_binary_t hash = {
		.size = KR_CACHE_KEY_MAXLEN - val.len,
		.data = val.data + val.len,
	};
	int ret = dnssec_nsec3_hash(&dname, &nsec_p->libknot, &hash);
	if (ret != DNSSEC_EOK) return VAL_EMPTY;
	assert(hash.size == NSEC3_HASH_LEN);

	#else
	dnssec_binary_t hash = { .size = 0, .data = NULL };
	int ret = dnssec_nsec3_hash(&dname, &nsec_p->libknot, &hash);
	if (ret != DNSSEC_EOK) return VAL_EMPTY;
	if (hash.size != NSEC3_HASH_LEN || !hash.data) {
		assert(false);
		return VAL_EMPTY;
	}
	memcpy(knot_db_val_bound(val), hash.data, NSEC3_HASH_LEN);
	free(hash.data);
	#endif

	val.len += hash.size;
	return val;
}

/** Return h1 < h2, semantically on NSEC3 hashes. */
static inline bool nsec3_hash_ordered(const uint8_t *h1, const uint8_t *h2)
{
	return memcmp(h1, h2, NSEC3_HASH_LEN) < 0;
}

/** NSEC3 range search.
 *
 * \param key Pass output of key_NSEC3(k, ...)
 * \param nsec_p Restrict to this NSEC3 parameter-set.
 * \param value[out] The raw data of the NSEC3 cache record (optional; consistency checked).
 * \param exact_match[out] Whether the key was matched exactly or just covered (optional).
 * \param hash_low[out] Output the low end hash of covering NSEC3, pointing within DB (optional).
 * \param new_ttl[out] New TTL of the NSEC3 (optional).
 * \return Error message or NULL.
 * \note The function itself does *no* bitmap checks, e.g. RFC 6840 sec. 4.
 */
static const char * find_leq_NSEC3(struct kr_cache *cache, const struct kr_query *qry,
		const knot_db_val_t key, const struct key *k, const struct nsec_p *nsec_p,
		knot_db_val_t *value, bool *exact_match, const uint8_t **hash_low,
		uint32_t *new_ttl)
{
	/* Do the cache operation. */
	const size_t hash_off = key_nsec3_hash_off(k);
	if (!key.data || key.len < hash_off) {
		assert(false);
		return "range search ERROR";
	}
	knot_db_val_t key_found = key;
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read_leq, &key_found, &val);
		/* ^^ LATER(optim.): incrementing key and doing less-than search
		 * would probably be slightly more efficient with LMDB,
		 * but the code complexity would grow considerably. */
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
	const struct entry_h *eh = entry_h_consistent_NSEC(val);
	if (!eh) {
		/* This might be just finding something else than NSEC3 entry,
		 * in case we searched before the very first one in the zone. */
		return "range search found inconsistent entry";
	}
	/* Passing just zone name instead of owner. */
	int32_t new_ttl_ = get_new_ttl(eh, qry, k->zname, KNOT_RRTYPE_NSEC3,
					qry->timestamp.tv_sec);
	if (new_ttl_ < 0 || !kr_rank_test(eh->rank, KR_RANK_SECURE)) {
		return "range search found stale or insecure entry";
		/* TODO: remove the stale record *and* retry,
		 * in case we haven't run off.  Perhaps start by in_zone check. */
	}
	if (new_ttl) {
		*new_ttl = new_ttl_;
	}
	if (hash_low) {
		*hash_low = (uint8_t *)key_found.data + hash_off;
	}
	if (is_exact) {
		/* Nothing else to do. */
		return NULL;
	}
	/* The NSEC3 starts strictly before our target name;
	 * now check that it still belongs into that zone and chain. */
	const uint8_t *nsec_p_raw = eh->data + KR_CACHE_RR_COUNT_SIZE
					+ 2 /* RDLENGTH from rfc1034 */;
	const int nsec_p_len = nsec_p_rdlen(nsec_p_raw);
	const bool same_chain = key_found.len == hash_off + NSEC3_HASH_LEN
		/* CACHE_KEY_DEF */
		&& memcmp(key.data, key_found.data, hash_off) == 0
		/* exact comparison of NSEC3 parameters */
		&& nsec_p_len == nsec_p_rdlen(nsec_p->raw)
		&& memcmp(nsec_p_raw, nsec_p->raw, nsec_p_len) == 0;
	if (!same_chain) {
		return "range search miss (!same_chain)";
	}
	/* We know it starts before sname, so let's check the other end.
	 * A. find the next hash and check its length. */
	if (KR_CACHE_RR_COUNT_SIZE != 2 || get_uint16(eh->data) == 0) {
		assert(false);
		return "ERROR";
		/* TODO: more checks?  Also, `next` computation is kinda messy. */
	}
	const uint8_t *hash_next = nsec_p_raw + nsec_p_len
				 + sizeof(uint8_t) /* hash length from rfc5155 */;
	if (hash_next[-1] != NSEC3_HASH_LEN) {
		return "unexpected next hash length";
	}
	/* B. do the actual range check. */
	const uint8_t * const hash_searched = (uint8_t *)key.data + hash_off;
	bool covers = /* we know for sure that the low end is before the searched name */
		nsec3_hash_ordered(hash_searched, hash_next)
		/* and the wrap-around case */
		|| nsec3_hash_ordered(hash_next, (const uint8_t *)key_found.data + hash_off);
	if (!covers) {
		return "range search miss (!covers)";
	}
	return NULL;
}

/** Extract textual representation of NSEC3 hash from a cache key.
 * \param text must have length at least NSEC3_HASH_TXT_LEN+1 (will get 0-terminated). */
static void key_NSEC3_hash2text(const knot_db_val_t key, char *text)
{
	assert(key.data && key.len > NSEC3_HASH_LEN);
	const uint8_t *hash_raw = knot_db_val_bound(key) - NSEC3_HASH_LEN;
			/* CACHE_KEY_DEF ^^ */
	int len = base32hex_encode(hash_raw, NSEC3_HASH_LEN, (uint8_t *)text,
				   NSEC3_HASH_TXT_LEN);
	assert(len == NSEC3_HASH_TXT_LEN); (void)len;
	text[NSEC3_HASH_TXT_LEN] = '\0';
}

/** Reconstruct a name into a buffer (assuming length at least KNOT_DNAME_MAXLEN).
 * \return kr_ok() or error code (<0). */
static int dname_wire_reconstruct(knot_dname_t *buf, const knot_dname_t *zname,
				  const uint8_t *hash_raw)
{
	int len = base32hex_encode(hash_raw, NSEC3_HASH_LEN, buf + 1, NSEC3_HASH_TXT_LEN);
	if (len != NSEC3_HASH_TXT_LEN) {
		assert(false);
		return kr_error(EINVAL);
	}
	buf[0] = len;
	int ret = knot_dname_to_wire(buf + 1 + len, zname, KNOT_DNAME_MAXLEN - 1 - len);
	return ret < 0 ? kr_error(ret) : kr_ok();
}

static void nsec3_hash2text(const knot_dname_t *owner, char *text)
{
	assert(owner[0] == NSEC3_HASH_TXT_LEN);
	memcpy(text, owner + 1, MIN(owner[0], NSEC3_HASH_TXT_LEN));
	text[NSEC3_HASH_TXT_LEN] = '\0';
}

int nsec3_encloser(struct key *k, struct answer *ans,
		   const int sname_labels, int *clencl_labels,
		   const struct kr_query *qry, struct kr_cache *cache)
{
	static const int ESKIP = ABS(ENOENT);
	/* Basic sanity check. */
	const bool ok = k && k->zname && ans && clencl_labels
			&& qry && cache;
	if (!ok) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}

	/*** Find the closest encloser - cycle: name starting at sname,
	 * proceeding while longer than zname, shortening by one label on step.
	 * We need a pair where a name doesn't exist *and* its parent does. */
		/* LATER(optim.): perhaps iterate in the other order - that
		 * should help significantly against deep queries where we have
		 * a shallow proof in the cache.  We can also optimize by using
		 * only exact search unless we had a match in the previous iteration. */
	const int zname_labels = knot_dname_labels(k->zname, NULL);
	int last_nxproven_labels = -1;
	const knot_dname_t *name = qry->sname;
	for (int name_labels = sname_labels; name_labels >= zname_labels;
					--name_labels, name += 1 + name[0]) {
		/* Find a previous-or-equal NSEC3 in cache covering the name,
		 * checking TTL etc. */
		const knot_db_val_t key = key_NSEC3_name(k, name, false, &ans->nsec_p);
		if (!key.data) continue;
		WITH_VERBOSE(qry) {
			char hash_txt[NSEC3_HASH_TXT_LEN + 1];
			key_NSEC3_hash2text(key, hash_txt);
			VERBOSE_MSG(qry, "=> NSEC3 depth %d: hash %s\n",
					name_labels - zname_labels, hash_txt);
		}
		knot_db_val_t val = { NULL, 0 };
		bool exact_match;
		uint32_t new_ttl;
		const uint8_t *hash_low;
		const char *err = find_leq_NSEC3(cache, qry, key, k, &ans->nsec_p, &val,
						 &exact_match, &hash_low, &new_ttl);
		if (err) {
			WITH_VERBOSE(qry) {
				auto_free char *name_str = kr_dname_text(name);
				VERBOSE_MSG(qry, "=> NSEC3 encloser error for %s: %s\n",
						name_str, err);
			}
			continue;
		}
		if (exact_match && name_labels != sname_labels
				&& name_labels + 1 != last_nxproven_labels) {
			/* This name exists (checked rank and TTL), and it's
			 * neither of the two interesting cases, so we do not
			 * keep searching for non-existence above this name. */
			VERBOSE_MSG(qry,
				"=> NSEC3 encloser: only found existence of an ancestor\n");
			return ESKIP;
		}
		/* Optimization: avoid the rest of the last iteration if pointless. */
		if (!exact_match && name_labels == zname_labels
		    && last_nxproven_labels != name_labels + 1) {
			break;
		}

		/* Basic checks OK -> materialize data, cleaning any previous
		 * records on that answer index (unsuccessful attempts). */
		knot_dname_t owner[KNOT_DNAME_MAXLEN];
		{
			int ret = dname_wire_reconstruct(owner, k->zname, hash_low);
			if (unlikely(ret)) continue;
		}
		const int ans_id = (exact_match && name_labels + 1 == last_nxproven_labels)
				 ? AR_CPE : AR_NSEC;
		{
			const struct entry_h *nsec_eh = val.data;
			memset(&ans->rrsets[ans_id], 0, sizeof(ans->rrsets[ans_id]));
			int ret = entry2answer(ans, ans_id, nsec_eh, knot_db_val_bound(val),
						owner, KNOT_RRTYPE_NSEC3, new_ttl);
			if (ret) return kr_error(ret);
		}

		if (!exact_match) {
			/* Non-existence proven, but we don't know if `name`
			 * is the next closer name.
			 * Note: we don't need to check for the sname being
			 * delegated away by this record, as with NSEC3 only
			 * *exact* match on an ancestor could do that. */
			last_nxproven_labels = name_labels;
			WITH_VERBOSE(qry) {
				char hash_low_txt[NSEC3_HASH_TXT_LEN + 1];
				nsec3_hash2text(owner, hash_low_txt);
				VERBOSE_MSG(qry,
					"=> NSEC3 depth %d: covered by %s -> TODO, new TTL %d\n",
					name_labels - zname_labels, hash_low_txt, new_ttl);
			}
			continue;
		}

		/* Exactly matched NSEC3: two cases, one after another. */
		const knot_rrset_t *nsec_rr = ans->rrsets[ans_id].set.rr;
		const uint8_t *bm = knot_nsec3_bitmap(nsec_rr->rrs.rdata);
		uint16_t bm_size = knot_nsec3_bitmap_len(nsec_rr->rrs.rdata);
		assert(bm);
		if (name_labels == sname_labels) {
			if (kr_nsec_bitmap_nodata_check(bm, bm_size, qry->stype,
							nsec_rr->owner) != 0) {
				VERBOSE_MSG(qry,
					"=> NSEC3 sname: match but failed type check\n");
				return ESKIP;
			}
			/* NODATA proven; just need to add SOA+RRSIG later */
			VERBOSE_MSG(qry,
				"=> NSEC3 sname: match proved NODATA, new TTL %d\n",
				new_ttl);
			ans->rcode = PKT_NODATA;
			return kr_ok();

		} /* else */

		assert(name_labels + 1 == last_nxproven_labels);
		if (kr_nsec_children_in_zone_check(bm, bm_size) != 0) {
			VERBOSE_MSG(qry,
				"=> NSEC3 encloser: found but delegated (or error)\n");
			return ESKIP;
		}
		/* NXDOMAIN proven *except* for wildcards. */
		WITH_VERBOSE(qry) {
			auto_free char *name_str = kr_dname_text(name);
			VERBOSE_MSG(qry,
				"=> NSEC3 encloser: confirmed as %s, new TTL %d\n",
				name_str, new_ttl);
		}
		*clencl_labels = name_labels;
		ans->rcode = PKT_NXDOMAIN;
		/* Avoid repeated NSEC3 - remove either if the hashes match.
		 * This is very unlikely in larger zones: 1/size (per attempt).
		 * Well, deduplication would happen anyway when the answer
		 * from cache is read by kresd (internally). */
		if (unlikely(0 == memcmp(ans->rrsets[AR_NSEC].set.rr->owner + 1,
					 ans->rrsets[AR_CPE ].set.rr->owner + 1,
					 NSEC3_HASH_LEN))) {
			memset(&ans->rrsets[AR_CPE], 0, sizeof(ans->rrsets[AR_CPE]));
			/* LATER(optim.): perhaps check this earlier and avoid some work? */
		}
		return kr_ok();
	}

	/* We've ran out of options. */
	if (last_nxproven_labels > 0) {
		/* We didn't manage to prove existence of the closest encloser,
		 * meaning the only chance left is a *positive* wildcard record. */
		*clencl_labels = last_nxproven_labels - 1;
		ans->rcode = PKT_NXDOMAIN;
		/* FIXME: review */
	}
	return ESKIP;
}

int nsec3_src_synth(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    const struct kr_query *qry, struct kr_cache *cache)
{
	/* Find a previous-or-equal NSEC3 in cache covering or matching
	 * the source of synthesis, checking TTL etc. */
	const knot_db_val_t key = key_NSEC3_name(k, clencl_name, true, &ans->nsec_p);
	if (!key.data) return kr_error(1);
	WITH_VERBOSE(qry) {
		char hash_txt[NSEC3_HASH_TXT_LEN + 1];
		key_NSEC3_hash2text(key, hash_txt);
		VERBOSE_MSG(qry, "=> NSEC3 wildcard: hash %s\n", hash_txt);
	}
	knot_db_val_t val = { NULL, 0 };
	bool exact_match;
	uint32_t new_ttl;
	const uint8_t *hash_low;
	const char *err = find_leq_NSEC3(cache, qry, key, k, &ans->nsec_p, &val,
					 &exact_match, &hash_low, &new_ttl);
	if (err) {
		VERBOSE_MSG(qry, "=> NSEC3 wildcard: %s\n", err);
		return kr_ok();
	}

	/* LATER(optim.): avoid duplicities in answer. */

	/* Basic checks OK -> materialize the data (speculatively). */
	knot_dname_t owner[KNOT_DNAME_MAXLEN];
	{
		int ret = dname_wire_reconstruct(owner, k->zname, hash_low);
		if (unlikely(ret)) return kr_ok();
		const struct entry_h *nsec_eh = val.data;
		ret = entry2answer(ans, AR_WILD, nsec_eh, knot_db_val_bound(val),
				   owner, KNOT_RRTYPE_NSEC3, new_ttl);
		if (ret) return kr_error(ret);
	}
	const knot_rrset_t *nsec_rr = ans->rrsets[AR_WILD].set.rr;

	if (!exact_match) {
		/* The record proves wildcard non-existence. */
		WITH_VERBOSE(qry) {
			char hash_low_txt[NSEC3_HASH_TXT_LEN + 1];
			nsec3_hash2text(owner, hash_low_txt);
			VERBOSE_MSG(qry,
				"=> NSEC3 wildcard: covered by %s -> TODO, new TTL %d\n",
				hash_low_txt, new_ttl);
		}
		return AR_SOA;
	}

	/* The wildcard exists.  Find if it's NODATA - check type bitmap. */
	const uint8_t *bm = knot_nsec3_bitmap(nsec_rr->rrs.rdata);
	uint16_t bm_size = knot_nsec3_bitmap_len(nsec_rr->rrs.rdata);
	assert(bm);
	if (kr_nsec_bitmap_nodata_check(bm, bm_size, qry->stype, nsec_rr->owner) == 0) {
		/* NODATA proven; just need to add SOA+RRSIG later */
		VERBOSE_MSG(qry, "=> NSEC3 wildcard: match proved NODATA, new TTL %d\n",
				 new_ttl);
		ans->rcode = PKT_NODATA;
		return AR_SOA;

	} /* else */
	/* The data probably exists -> don't add this NSEC3
	 * and (later) try to find the real wildcard data */
	VERBOSE_MSG(qry, "=> NSEC3 wildcard: should exist (or error)\n");
	ans->rcode = PKT_NOERROR;
	memset(&ans->rrsets[AR_WILD], 0, sizeof(ans->rrsets[AR_WILD]));
	return kr_ok();
}

