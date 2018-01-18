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
 * Implementation of chaining in struct entry_h.  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"


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

/* See the header file. */
int entry_h_seek(knot_db_val_t *val, uint16_t type)
{
	uint16_t ktype;
	switch (type) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		ktype = KNOT_RRTYPE_NS;
		break;
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
	return present ? kr_ok() : kr_error(ENOENT);
}


/* See the header file. */
int entry_h_splice(
	knot_db_val_t *val_new_entry, uint8_t rank,
	const knot_db_val_t key, const uint16_t ktype, const uint16_t type,
	const knot_dname_t *owner/*log only*/,
	const struct kr_query *qry, struct kr_cache *cache)
{
	static const knot_db_val_t VAL_EMPTY = { NULL, 0 };
	const bool ok = val_new_entry && val_new_entry->len > 0;
	if (!ok) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}

	/* Find the whole entry-set and the particular entry within. */
	knot_db_val_t val_orig_all = VAL_EMPTY, val_orig_entry = VAL_EMPTY;
	const struct entry_h *eh_orig = NULL;
	if (!kr_rank_test(rank, KR_RANK_SECURE) || ktype == KNOT_RRTYPE_NS) {
		int ret = cache_op(cache, read, &key, &val_orig_all, 1);
		if (ret) val_orig_all = VAL_EMPTY;
		val_orig_entry = val_orig_all;
		switch (entry_h_seek(&val_orig_entry, type)) {
		case 0:
			ret = entry_h_len(val_orig_entry);
			if (ret >= 0) {
				val_orig_entry.len = ret;
				eh_orig = entry_h_consistent(val_orig_entry, ktype);
				if (eh_orig) {
					break;
				}
			} /* otherwise fall through */
		default:
			val_orig_entry = val_orig_all = VAL_EMPTY;
		case -ENOENT:
			val_orig_entry.len = 0;
			break;
		};
		assert(val_orig_entry.data + val_orig_entry.len
			<= val_orig_all.data + val_orig_all.len);
	}

	if (!kr_rank_test(rank, KR_RANK_SECURE) && eh_orig) {
		/* If equal rank was accepted, spoofing a *single* answer would be
		 * enough to e.g. override NS record in AUTHORITY section.
		 * This way they would have to hit the first answer
		 * (whenever TTL nears expiration).
		 * Stale-serving is NOT considered, but TTL 1 would be considered
		 * as expiring anyway, ... */
		int32_t old_ttl = get_new_ttl(eh_orig, qry, NULL, 0);
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

	/* LATER: enable really having multiple entries. */
	val_orig_all = val_orig_entry = VAL_EMPTY;

	/* Obtain new storage from cache.
	 * Note: this does NOT invalidate val_orig_all.data.
	 * FIX ME LATER: possibly wrong, as transaction may be switched RO->RW
	 * (conditioned on allowing multiple entries above) */
	ssize_t storage_size = val_orig_all.len - val_orig_entry.len
				+ val_new_entry->len;
	assert(storage_size > 0);
	knot_db_val_t val = { .len = storage_size, .data = NULL };
	int ret = cache_op(cache, write, &key, &val, 1);
	if (ret || !val.data || !val.len) {
		/* Clear cache if overfull.  It's nontrivial to do better with LMDB.
		 * LATER: some garbage-collection mechanism. */
		if (ret == kr_error(ENOSPC)) {
			ret = kr_cache_clear(cache);
			const char *msg = "[cache] clearing because overfull, ret = %d\n";
			if (ret) {
				kr_log_error(msg, ret);
			} else {
				kr_log_info(msg, ret);
				ret = kr_error(ENOSPC);
			}
			return ret;
		}
		assert(ret); /* otherwise "succeeding" but `val` is bad */
		VERBOSE_MSG(qry, "=> failed backend write, ret = %d\n", ret);
		return kr_error(ret ? ret : ENOSPC);
	}

	/* Write original data before entry, if any. */
	const ssize_t len_before = val_orig_entry.data - val_orig_all.data;
	assert(len_before >= 0);
	if (len_before) {
		assert(ktype == KNOT_RRTYPE_NS);
		memcpy(val.data, val_orig_all.data, len_before);
	}
	/* Write original data after entry, if any. */
	const ssize_t len_after = val_orig_all.len - len_before - val_orig_entry.len;
	assert(len_after >= 0);
	assert(len_before + val_orig_entry.len + len_after == val_orig_all.len
		&& len_before + val_new_entry->len + len_after == storage_size);
	if (len_after) {
		assert(ktype == KNOT_RRTYPE_NS);
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
		if (val_orig_all.len) {
			const struct entry_h *eh0 = val_orig_all.data;
			/* ENTRY_H_FLAGS */
			eh->nsec1_pos = eh0->nsec1_pos;
			eh->nsec3_cnt = eh0->nsec3_cnt;
			eh->has_ns    = eh0->has_ns;
			eh->has_cname = eh0->has_cname;
			eh->has_dname = eh0->has_dname;
			eh->has_optout = eh0->has_optout;
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

