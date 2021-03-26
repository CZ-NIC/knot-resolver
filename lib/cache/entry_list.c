/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Implementation of chaining in struct entry_h.  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"
#include "lib/utils.h"


static int entry_h_len(knot_db_val_t val);


void entry_list_memcpy(struct entry_apex *ea, entry_list_t list)
{
	if (!kr_assume(ea))
		return;
	memset(ea, 0, offsetof(struct entry_apex, data));
	ea->has_ns	= list[EL_NS	].len;
	ea->has_cname	= list[EL_CNAME	].len;
	ea->has_dname	= list[EL_DNAME	].len;
	for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i) {
		ea->nsecs[i] =   list[i].len == 0 ? 0 :
				(list[i].len == 4 ? 1 : 3);
	}
	uint8_t *it = ea->data;
	for (int i = 0; i < EL_LENGTH; ++i) {
		if (list[i].data) {
			memcpy(it, list[i].data, list[i].len);
			/* LATER(optim.): coalesce consecutive writes? */
		} else {
			list[i].data = it;
		}
		it += to_even(list[i].len);
	}
}

int entry_list_parse(const knot_db_val_t val, entry_list_t list)
{
	if (!kr_assume(val.data && val.len && list))
		return kr_error(EINVAL);
	/* Parse the apex itself (nsec parameters). */
	const struct entry_apex *ea = entry_apex_consistent(val);
	if (!ea) {
		return kr_error(EILSEQ);
	}
	const uint8_t *it = ea->data,
		*it_bound = knot_db_val_bound(val);
	for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i) {
		if (it > it_bound) {
			return kr_error(EILSEQ);
		}
		list[i].data = (void *)it;
		switch (ea->nsecs[i]) {
		case 0:
			list[i].len = 0;
			break;
		case 1:
			list[i].len = sizeof(uint32_t); /* just timestamp */
			break;
		case 3: { /* timestamp + NSEC3PARAM wire */
			if (it + sizeof(uint32_t) + 4 > it_bound) {
				return kr_error(EILSEQ);
			}
			list[i].len = sizeof(uint32_t)
				+ nsec_p_rdlen(it + sizeof(uint32_t));
			break;
			}
		default:
			return kr_error(EILSEQ);
		};
		it += to_even(list[i].len);
	}
	/* Parse every entry_h. */
	for (int i = ENTRY_APEX_NSECS_CNT; i < EL_LENGTH; ++i) {
		list[i].data = (void *)it;
		bool has_type;
		switch (i) {
		case EL_NS:	has_type = ea->has_ns;		break;
		case EL_CNAME:	has_type = ea->has_cname;	break;
		case EL_DNAME:	has_type = ea->has_dname;	break;
		default:
			(void)!kr_assume(!EINVAL);
			return kr_error(EINVAL); /* something very bad */
		}
		if (!has_type) {
			list[i].len = 0;
			continue;
		}
		if (!kr_assume(it < it_bound))
			return kr_error(EILSEQ);
		const int len = entry_h_len(
			(knot_db_val_t){ .data = (void *)it, .len = it_bound - it });
		if (!kr_assume(len >= 0))
			return kr_error(len);
		list[i].len = len;
		it += to_even(len);
	}
	kr_require(it == it_bound);  // TODO maybe kr_assume?
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
	const uint8_t *d = eh->data; /* iterates over the data in entry */
	const uint8_t *data_bound = knot_db_val_bound(val);
	if (d >= data_bound) return kr_error(EILSEQ);
	if (!eh->is_packet) { /* Positive RRset + its RRsig set (may be empty). */
		int sets = 2;
		while (sets-- > 0) {
			d += KR_CACHE_RR_COUNT_SIZE + rdataset_dematerialized_size(d, NULL);
			if (!kr_assume(d <= data_bound))
				return kr_error(EILSEQ);
		}
	} else { /* A "packet" (opaque ATM). */
		uint16_t len;
		if (d + sizeof(len) > data_bound) return kr_error(EILSEQ);
		memcpy(&len, d, sizeof(len));
		d += 2 + to_even(len);
	}
	if (!kr_assume(d <= data_bound))
		return kr_error(EILSEQ);
	return d - (uint8_t *)val.data;
}

struct entry_apex * entry_apex_consistent(knot_db_val_t val)
{
	//XXX: check lengths, etc.
	return val.data;
}

/* See the header file. */
int entry_h_seek(knot_db_val_t *val, uint16_t type)
{
	int i = -1;
	switch (type) {
	case KNOT_RRTYPE_NS:	i = EL_NS;	break;
	case KNOT_RRTYPE_CNAME:	i = EL_CNAME;	break;
	case KNOT_RRTYPE_DNAME:	i = EL_DNAME;	break;
	default:		return kr_ok();
	}

	entry_list_t el;
	int ret = entry_list_parse(*val, el);
	if (ret) return ret;
	*val = el[i];
	return val->len ? kr_ok() : kr_error(ENOENT);
}

static int cache_write_or_clear(struct kr_cache *cache, const knot_db_val_t *key,
				knot_db_val_t *val, const struct kr_query *qry)
{
	int ret = cache_op(cache, write, key, val, 1);
	if (!ret) return kr_ok();

	if (ret != kr_error(ENOSPC)) { /* failing a write isn't too bad */
		VERBOSE_MSG(qry, "=> failed backend write, ret = %d\n", ret);
		return kr_error(ret);
	}

	/* Cache is overfull.  Using kres-cache-gc service should prevent this.
	 * As a fallback, try clearing it. */
	ret = kr_cache_clear(cache);
	switch (ret) {
	default:
		kr_log_error("CRITICAL: clearing cache failed: %s; fatal error, aborting\n",
				kr_strerror(ret));
		abort();
	case 0:
		kr_log_info("[cache] overfull cache cleared\n");
	case -EAGAIN: // fall-through; krcachelock race -> retry later
		return kr_error(ENOSPC);
	}
}


/* See the header file. */
int entry_h_splice(
	knot_db_val_t *val_new_entry, uint8_t rank,
	const knot_db_val_t key, const uint16_t ktype, const uint16_t type,
	const knot_dname_t *owner/*log only*/,
	const struct kr_query *qry, struct kr_cache *cache, uint32_t timestamp)
{
	//TODO: another review, perhaps incuding the API
	if (!kr_assume(val_new_entry && val_new_entry->len > 0))
		return kr_error(EINVAL);

	int i_type;
	switch (type) {
	case KNOT_RRTYPE_NS:	i_type = EL_NS;		break;
	case KNOT_RRTYPE_CNAME:	i_type = EL_CNAME;	break;
	case KNOT_RRTYPE_DNAME:	i_type = EL_DNAME;	break;
	default:		i_type = 0;
	}

	/* Get eh_orig (original entry), and also el list if multi-entry case. */
	const struct entry_h *eh_orig = NULL;
	entry_list_t el;
	int ret = -1;
	if (!kr_rank_test(rank, KR_RANK_SECURE) || ktype == KNOT_RRTYPE_NS) {
		knot_db_val_t val;
		ret = cache_op(cache, read, &key, &val, 1);
		if (i_type) {
			if (!ret) ret = entry_list_parse(val, el);
			if (ret) memset(el, 0, sizeof(el));
			val = el[i_type];
		}
		/* val is on the entry, in either case (or error) */
		if (!ret) {
			eh_orig = entry_h_consistent_E(val, type);
		}
	} else {
		/* We want to fully overwrite the entry, so don't even read it. */
		memset(el, 0, sizeof(el));
	}

	if (!kr_rank_test(rank, KR_RANK_SECURE) && eh_orig) {
		/* If equal rank was accepted, spoofing a *single* answer would be
		 * enough to e.g. override NS record in AUTHORITY section.
		 * This way they would have to hit the first answer
		 * (whenever TTL nears expiration).
		 * Stale-serving is NOT considered, but TTL 1 would be considered
		 * as expiring anyway, ... */
		int32_t old_ttl = get_new_ttl(eh_orig, qry, NULL, 0, timestamp);
		if (old_ttl > 0 && !is_expiring(eh_orig->ttl, old_ttl)
		    && rank <= eh_orig->rank) {
			WITH_VERBOSE(qry) {
				auto_free char *type_str = kr_rrtype_text(type),
					*owner_str = kr_dname_text(owner);
				VERBOSE_MSG(qry, "=> not overwriting %s %s\n",
						type_str, owner_str);
			}
			return kr_error(EEXIST);
		}
	}

	if (!i_type) {
		/* The non-list types are trivial now. */
		return cache_write_or_clear(cache, &key, val_new_entry, qry);
	}
	/* Now we're in trouble.  In some cases, parts of data to be written
	 * is an lmdb entry that may be invalidated by our write request.
	 * (lmdb does even in-place updates!) Therefore we copy all into a buffer.
	 * LATER(optim.): do this only when neccessary, or perhaps another approach.
	 * This is also complicated by the fact that the val_new_entry part
	 * is to be written *afterwards* by the caller.
	 */
	el[i_type] = (knot_db_val_t){
		.len = val_new_entry->len,
		.data = NULL, /* perhaps unclear in the entry_h_splice() API */
	};
	knot_db_val_t val = {
		.len = entry_list_serial_size(el),
		.data = NULL,
	};
	uint8_t buf[val.len];
	entry_list_memcpy((struct entry_apex *)buf, el);
	ret = cache_write_or_clear(cache, &key, &val, qry);
	if (ret) return kr_error(ret);
	memcpy(val.data, buf, val.len); /* we also copy the "empty" space, but well... */
	val_new_entry->data = (uint8_t *)val.data
			    + ((uint8_t *)el[i_type].data - buf);
	return kr_ok();
}

