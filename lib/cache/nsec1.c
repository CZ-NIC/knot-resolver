/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Implementation of NSEC (1) handling.  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"
#include "lib/dnssec/nsec.h"
#include "lib/layer/iterate.h"


/** Reconstruct a name into a buffer (assuming length at least KNOT_DNAME_MAXLEN).
 * \return kr_ok() or error code (<0). */
static int dname_wire_reconstruct(knot_dname_t *buf, const struct key *k,
		 knot_db_val_t kwz)
{
	/* Reconstruct from key: first the ending, then zone name. */
	int ret = knot_dname_lf2wire(buf, kwz.len, kwz.data);
	if (ret < 0) {
		VERBOSE_MSG(NULL, "=> NSEC: LF2wire ret = %d\n", ret);
		assert(false);
		return ret;
	}
		/* The last written byte is the zero label for root -> overwrite. */
	knot_dname_t *zone_start = buf + ret - 1;
	assert(*zone_start == '\0');
	ret = knot_dname_to_wire(zone_start, k->zname, KNOT_DNAME_MAXLEN - kwz.len);
	if (ret != k->zlf_len + 1) {
		assert(false);
		return ret < 0 ? ret : kr_error(EILSEQ);
	}
	return kr_ok();
}


knot_db_val_t key_NSEC1(struct key *k, const knot_dname_t *name, bool add_wildcard)
{
	/* we basically need dname_lf with two bytes added
	 * on a correct place within the name (the cut) */
	int ret;
	const bool ok = k && name
		&& !(ret = kr_dname_lf(k->buf, name, add_wildcard));
	if (!ok) {
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}

	uint8_t *begin = k->buf + 1 + k->zlf_len; /* one byte after zone's zero */
	uint8_t *end = k->buf + 1 + k->buf[0]; /* we don't use the final zero in key,
						* but move it anyway */
	if (end < begin) {
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}
	int key_len;
	if (end > begin) {
		memmove(begin + 2, begin, end - begin);
		key_len = k->buf[0] + 1;
	} else {
		key_len = k->buf[0] + 2;
	}
	/* CACHE_KEY_DEF: key == zone's dname_lf + '\0' + '1' + dname_lf
	 * of the name within the zone without the final 0.  Iff the latter is empty,
	 * there's no zero to cut and thus the key_len difference.
	 */
	begin[0] = 0;
	begin[1] = '1'; /* tag for NSEC1 */
	k->type = KNOT_RRTYPE_NSEC;

	/*
	VERBOSE_MSG(NULL, "<> key_NSEC1; name: ");
	kr_dname_print(name, add_wildcard ? "*." : "" , " ");
	kr_log_verbose("(zone name LF length: %d; total key length: %d)\n",
			k->zlf_len, key_len);
	*/

	return (knot_db_val_t){ k->buf + 1, key_len };
}


/** Assuming that k1 < k4, find where k2 is.  (Considers DNS wrap-around.)
 *
 * \return Intuition: position of k2 among kX.
 *	0: k2 < k1;  1: k1 == k2;  2: k1 is a prefix of k2 < k4;
 *	3: k1 < k2 < k4 (and not 2);  4: k2 == k4;  5: k2 > k4
 * \note k1.data may be NULL, meaning assumption that k1 < k2 and not a prefix
 *       (i.e. return code will be > 2)
 */
static int kwz_between(knot_db_val_t k1, knot_db_val_t k2, knot_db_val_t k4)
{
	assert(k2.data && k4.data);
	/* CACHE_KEY_DEF; we need to beware of one key being a prefix of another */
	int ret_maybe; /**< result, assuming we confirm k2 < k4 */
	if (k1.data) {
		const int cmp12 = memcmp(k1.data, k2.data, MIN(k1.len, k2.len));
		if (cmp12 == 0 && k1.len == k2.len) /* iff k1 == k2 */
			return 1;
		if (cmp12 > 0 || (cmp12 == 0 && k1.len > k2.len)) /* iff k1 > k2 */
			return 0;
		ret_maybe = cmp12 == 0 ? 2 : 3;
	} else {
		ret_maybe = 3;
	}
	if (k4.len == 0) { /* wrap-around */
		return k2.len > 0 ? ret_maybe : 4;
	} else {
		const int cmp24 = memcmp(k2.data, k4.data, MIN(k2.len, k4.len));
		if (cmp24 == 0 && k2.len == k4.len) /* iff k2 == k4 */
			return 4;
		if (cmp24 > 0 || (cmp24 == 0 && k2.len > k4.len)) /* iff k2 > k4 */
			return 5;
		return ret_maybe;
	}
}


/** NSEC1 range search.
 *
 * \param key Pass output of key_NSEC1(k, ...)
 * \param value[out] The raw data of the NSEC cache record (optional; consistency checked).
 * \param exact_match[out] Whether the key was matched exactly or just covered (optional).
 * \param kwz_low[out] Output the low end of covering NSEC, pointing within DB (optional).
 * \param kwz_high[in,out] Storage for the high end of covering NSEC (optional).
 * 		It's only set if !exact_match.
 * \param new_ttl[out] New TTL of the NSEC (optional).
 * \return Error message or NULL.
 * \note The function itself does *no* bitmap checks, e.g. RFC 6840 sec. 4.
 */
static const char * find_leq_NSEC1(struct kr_cache *cache, const struct kr_query *qry,
			const knot_db_val_t key, const struct key *k, knot_db_val_t *value,
			bool *exact_match, knot_db_val_t *kwz_low, knot_db_val_t *kwz_high,
			uint32_t *new_ttl)
{
	/* Do the cache operation. */
	const size_t nwz_off = key_nwz_off(k);
	if (!key.data || key.len < nwz_off) {
		assert(false);
		return "range search ERROR";
	}
	knot_db_val_t key_nsec = key;
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read_leq, &key_nsec, &val);
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
		/* This might be just finding something else than NSEC1 entry,
		 * in case we searched before the very first one in the zone. */
		return "range search found inconsistent entry";
	}
	/* Passing just zone name instead of owner, as we don't
	 * have it reconstructed at this point. */
	int32_t new_ttl_ = get_new_ttl(eh, qry, k->zname, KNOT_RRTYPE_NSEC,
					qry->timestamp.tv_sec);
	if (new_ttl_ < 0 || !kr_rank_test(eh->rank, KR_RANK_SECURE)) {
		return "range search found stale or insecure entry";
		/* TODO: remove the stale record *and* retry,
		 * in case we haven't run off.  Perhaps start by in_zone check. */
	}
	if (new_ttl) {
		*new_ttl = new_ttl_;
	}
	if (kwz_low) {
		*kwz_low = (knot_db_val_t){
			.data = (uint8_t *)key_nsec.data + nwz_off,
			.len = key_nsec.len - nwz_off,
		};	/* CACHE_KEY_DEF */
	}
	if (is_exact) {
		/* Nothing else to do. */
		return NULL;
	}
	/* The NSEC starts strictly before our target name;
	 * now check that it still belongs into that zone. */
	const bool nsec_in_zone = key_nsec.len >= nwz_off
		/* CACHE_KEY_DEF */
		&& memcmp(key.data, key_nsec.data, nwz_off) == 0;
	if (!nsec_in_zone) {
		return "range search miss (!nsec_in_zone)";
	}
	/* We know it starts before sname, so let's check the other end.
	 * 1. construct the key for the next name - kwz_hi. */
	/* it's *full* name ATM */
	/* Technical complication: memcpy is safe for unaligned case (on non-x86) */
	__typeof__(((knot_rdata_t *)NULL)->len) next_len;
	const uint8_t *next_data;
	{	/* next points to knot_rdata_t but possibly unaligned */
		const uint8_t *next = eh->data + KR_CACHE_RR_COUNT_SIZE;
		memcpy(&next_len, next + offsetof(knot_rdata_t, len), sizeof(next_len));
		next_data = next + offsetof(knot_rdata_t, data);
	}
	if (KR_CACHE_RR_COUNT_SIZE != 2 || get_uint16(eh->data) == 0) {
		assert(false);
		return "ERROR";
		/* TODO: more checks? */
	}
	/*
	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> NSEC: next name: ");
		kr_dname_print(next, "", "\n");
	}
	*/
	knot_dname_t ch_buf[KNOT_DNAME_MAXLEN];
	knot_dname_t *chs = kwz_high ? kwz_high->data : ch_buf;
	if (!chs) {
		assert(false);
		return "EINVAL";
	}
	{
		/* Lower-case chs; see also RFC 6840 5.1.
		 * LATER(optim.): we do lots of copying etc. */
		knot_dname_t lower_buf[KNOT_DNAME_MAXLEN];
		ret = knot_dname_to_wire(lower_buf, next_data,
					 MIN(next_len, KNOT_DNAME_MAXLEN));
		if (ret < 0) { /* _ESPACE */
			return "range search found record with incorrect contents";
		}
		knot_dname_to_lower(lower_buf);
		ret = kr_dname_lf(chs, lower_buf, false);
	}
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
		.data = (void *)/*const-cast*/(k->buf + 1 + nwz_off),
		.len = k->buf[0] - k->zlf_len,
	};
	assert((ssize_t)(kwz_sname.len) >= 0);
	bool covers = /* we know for sure that the low end is before kwz_sname */
		3 == kwz_between((knot_db_val_t){ NULL, 0 }, kwz_sname, kwz_hi);
	if (!covers) {
		return "range search miss (!covers)";
	}
	if (kwz_high) {
		*kwz_high = kwz_hi;
	}
	return NULL;
}


int nsec1_encloser(struct key *k, struct answer *ans,
		   const int sname_labels, int *clencl_labels,
		   knot_db_val_t *cover_low_kwz, knot_db_val_t *cover_hi_kwz,
		   const struct kr_query *qry, struct kr_cache *cache)
{
	static const int ESKIP = ABS(ENOENT);
	/* Basic sanity check. */
	const bool ok = k && ans && clencl_labels && cover_low_kwz && cover_hi_kwz
			&& qry && cache;
	if (!ok) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	
	/* Find a previous-or-equal name+NSEC in cache covering the QNAME,
	 * checking TTL etc. */
	knot_db_val_t key = key_NSEC1(k, qry->sname, false);
	knot_db_val_t val = { NULL, 0 };
	bool exact_match;
	uint32_t new_ttl;
	const char *err = find_leq_NSEC1(cache, qry, key, k, &val,
			&exact_match, cover_low_kwz, cover_hi_kwz, &new_ttl);
	if (err) {
		VERBOSE_MSG(qry, "=> NSEC sname: %s\n", err);
		return ESKIP;
	}

	/* Get owner name of the record. */
	const knot_dname_t *owner;
	knot_dname_t owner_buf[KNOT_DNAME_MAXLEN];
	if (exact_match) {
		owner = qry->sname;
	} else {
		int ret = dname_wire_reconstruct(owner_buf, k, *cover_low_kwz);
		if (unlikely(ret)) return ESKIP;
		owner = owner_buf;
	}
	/* Basic checks OK -> materialize data. */
	{
		const struct entry_h *nsec_eh = val.data;
		int ret = entry2answer(ans, AR_NSEC, nsec_eh, knot_db_val_bound(val),
					owner, KNOT_RRTYPE_NSEC, new_ttl);
		if (ret) return kr_error(ret);
	}

	/* Final checks, split for matching vs. covering our sname. */
	const knot_rrset_t *nsec_rr = ans->rrsets[AR_NSEC].set.rr;
	const uint8_t *bm = knot_nsec_bitmap(nsec_rr->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(nsec_rr->rrs.rdata);
	assert(bm);

	if (exact_match) {
		if (kr_nsec_bitmap_nodata_check(bm, bm_size, qry->stype, nsec_rr->owner) != 0) {
			VERBOSE_MSG(qry,
				"=> NSEC sname: match but failed type check\n");
			return ESKIP;
		}
		/* NODATA proven; just need to add SOA+RRSIG later */
		VERBOSE_MSG(qry, "=> NSEC sname: match proved NODATA, new TTL %d\n",
				new_ttl);
		ans->rcode = PKT_NODATA;
		return kr_ok();
	} /* else */

	/* Inexact match.  First check if sname is delegated by that NSEC. */
	const int nsec_matched = knot_dname_matched_labels(nsec_rr->owner, qry->sname);
	const bool is_sub = nsec_matched == knot_dname_labels(nsec_rr->owner, NULL);
	if (is_sub && kr_nsec_children_in_zone_check(bm, bm_size) != 0) {
		VERBOSE_MSG(qry, "=> NSEC sname: covered but delegated (or error)\n");
		return ESKIP;
	}
	/* NXDOMAIN proven *except* for wildcards. */
	WITH_VERBOSE(qry) {
		auto_free char *owner_str = kr_dname_text(nsec_rr->owner),
			  *next_str = kr_dname_text(knot_nsec_next(nsec_rr->rrs.rdata));
		VERBOSE_MSG(qry, "=> NSEC sname: covered by: %s -> %s, new TTL %d\n",
				owner_str, next_str, new_ttl);
	}

	/* Find label count of the closest encloser.
	 * Both endpoints in an NSEC do exist (though possibly in a child zone)
	 * and any prefixes of those names as well (empty non-terminals),
	 * but nothing else exists inside this "triangle".
	 *
	 * Note that we have to lower-case the next name for comparison,
	 * even though we have canonicalized NSEC already; see RFC 6840 5.1.
	 * LATER(optim.): it might be faster to use the LFs we already have.
	 */
	knot_dname_t next[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire(next, knot_nsec_next(nsec_rr->rrs.rdata), sizeof(next));
	if (ret < 0) {
		assert(!ret);
		return kr_error(ret);
	}
	knot_dname_to_lower(next);
	*clencl_labels = MAX(
		nsec_matched,
		knot_dname_matched_labels(qry->sname, next)
		);

	/* Empty non-terminals don't need to have
	 * a matching NSEC record. */
	if (sname_labels == *clencl_labels) {
		ans->rcode = PKT_NODATA;
		VERBOSE_MSG(qry,
			"=> NSEC sname: empty non-terminal by the same RR\n");
	} else {
		ans->rcode = PKT_NXDOMAIN;
	}
	return kr_ok();
}

/** Verify non-existence after kwz_between() call. */
static bool nonexistence_ok(int cmp, const knot_rrset_t *rrs)
{
	if (cmp == 3) {
		return true;
	}
	if (cmp != 2) {
		return false;
	}
	const uint8_t *bm = knot_nsec_bitmap(rrs->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(rrs->rrs.rdata);
	return kr_nsec_children_in_zone_check(bm, bm_size) != 0;
}

int nsec1_src_synth(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    knot_db_val_t cover_low_kwz, knot_db_val_t cover_hi_kwz,
		    const struct kr_query *qry, struct kr_cache *cache)
{
	/* Construct key for the source of synthesis. */
	knot_db_val_t key = key_NSEC1(k, clencl_name, true);
	const size_t nwz_off = key_nwz_off(k);
	if (!key.data || key.len < nwz_off) {
		assert(false);
		return kr_error(1);
	}
	/* Check if our sname-covering NSEC also covers/matches SS. */
	knot_db_val_t kwz = {
		.data = (uint8_t *)key.data + nwz_off,
		.len = key.len - nwz_off,
	};
	assert((ssize_t)(kwz.len) >= 0);
	const int cmp = kwz_between(cover_low_kwz, kwz, cover_hi_kwz);
	if (nonexistence_ok(cmp, ans->rrsets[AR_NSEC].set.rr)) {
		VERBOSE_MSG(qry, "=> NSEC wildcard: covered by the same RR\n");
		return AR_SOA;
	}
	const knot_rrset_t *nsec_rr = NULL; /**< the wildcard proof NSEC */
	bool exact_match; /**< whether it matches the source of synthesis */
	if (cmp == 1) {
		exact_match = true;
		nsec_rr = ans->rrsets[AR_NSEC].set.rr;
	} else {
		/* Try to find the NSEC for SS. */
		knot_db_val_t val = { NULL, 0 };
		knot_db_val_t wild_low_kwz = { NULL, 0 };
		uint32_t new_ttl;
		const char *err = find_leq_NSEC1(cache, qry, key, k, &val,
				&exact_match, &wild_low_kwz, NULL, &new_ttl);
		if (err) {
			VERBOSE_MSG(qry, "=> NSEC wildcard: %s\n", err);
			return kr_ok();
		}
		/* Materialize the record into answer (speculatively). */
		knot_dname_t owner[KNOT_DNAME_MAXLEN];
		int ret = dname_wire_reconstruct(owner, k, wild_low_kwz);
		if (ret) return kr_error(ret);
		const struct entry_h *nsec_eh = val.data;
		ret = entry2answer(ans, AR_WILD, nsec_eh, knot_db_val_bound(val),
				   owner, KNOT_RRTYPE_NSEC, new_ttl);
		if (ret) return kr_error(ret);
		nsec_rr = ans->rrsets[AR_WILD].set.rr;
	}

	assert(nsec_rr);
	const uint32_t new_ttl_log =
		KR_LOG_LEVEL_IS(LOG_DEBUG) ? nsec_rr->ttl : -1;
	const uint8_t *bm = knot_nsec_bitmap(nsec_rr->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(nsec_rr->rrs.rdata);
	int ret;
	struct answer_rrset * const arw = &ans->rrsets[AR_WILD];
	if (!bm) {
		assert(false);
		ret = kr_error(1);
		goto clean_wild;
	}
	if (!exact_match) {
		/* Finish verification that the source of synthesis doesn't exist. */
		const int nsec_matched =
			knot_dname_matched_labels(nsec_rr->owner, clencl_name);
			/* we don't need to use the full source of synthesis ^ */
		const bool is_sub =
			nsec_matched == knot_dname_labels(nsec_rr->owner, NULL);
		if (is_sub && kr_nsec_children_in_zone_check(bm, bm_size) != 0) {
			VERBOSE_MSG(qry,
				"=> NSEC wildcard: covered but delegated (or error)\n");
			ret = kr_ok();
			goto clean_wild;
		}
		/* We have a record proving wildcard non-existence. */
		WITH_VERBOSE(qry) {
			auto_free char *owner_str = kr_dname_text(nsec_rr->owner),
				*next_str = kr_dname_text(knot_nsec_next(nsec_rr->rrs.rdata));
			VERBOSE_MSG(qry, "=> NSEC wildcard: covered by: %s -> %s, new TTL %d\n",
					owner_str, next_str, new_ttl_log);
		}
		return AR_SOA;
	}

	/* The wildcard exists.  Find if it's NODATA - check type bitmap. */
	if (kr_nsec_bitmap_nodata_check(bm, bm_size, qry->stype, nsec_rr->owner) == 0) {
		/* NODATA proven; just need to add SOA+RRSIG later */
		WITH_VERBOSE(qry) {
			const char *msg_start = "=> NSEC wildcard: match proved NODATA";
			if (arw->set.rr) {
				auto_free char *owner_str = kr_dname_text(nsec_rr->owner);
				VERBOSE_MSG(qry, "%s: %s, new TTL %d\n",
						msg_start, owner_str, new_ttl_log);
			} else {
				/* don't repeat the RR if it's the same */
				VERBOSE_MSG(qry, "%s, by the same RR\n", msg_start);
			}
		}
		ans->rcode = PKT_NODATA;
		return AR_SOA;

	} /* else */
	/* The data probably exists -> don't add this NSEC
	 * and (later) try to find the real wildcard data */
	VERBOSE_MSG(qry, "=> NSEC wildcard: should exist (or error)\n");
	ans->rcode = PKT_NOERROR;
	ret = kr_ok();
clean_wild:
	if (arw->set.rr) { /* we may have matched AR_NSEC */
		knot_rrset_free(arw->set.rr, ans->mm);
		arw->set.rr = NULL;
		knot_rdataset_clear(&arw->sig_rds, ans->mm);
	}
	return ret;
}

