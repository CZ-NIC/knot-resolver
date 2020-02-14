/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/** @file
 * Implementation of RRset (de)materialization, i.e. (de)serialization to storage
 * format used in cache (some repeated fields are omitted).  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"

int rdataset_dematerialize(const knot_rdataset_t *rds, uint8_t * restrict data)
{
	/* FIXME: either give up on even alignment and thus direct usability
	 * of rdatasets as they are in lmdb, or align inside cdb_* functions
	 * (request sizes one byte longer and shift iff on an odd address). */
	//if ((size_t)data & 1) VERBOSE_MSG(NULL, "dematerialize: odd address\n");
	//const uint8_t *data0 = data;
	if (!data) {
		assert(data);
		return kr_error(EINVAL);
	}
	const uint16_t rr_count = rds ? rds->count : 0;
	memcpy(data, &rr_count, sizeof(rr_count));
	data += sizeof(rr_count);
	if (rr_count) {
		size_t size = knot_rdataset_size(rds);
		memcpy(data, rds->rdata, size);
		data += size;
	}
	//VERBOSE_MSG(NULL, "dematerialized to %d B\n", (int)(data - data0));
	(void)data;
	return kr_ok();
}

/** Materialize a knot_rdataset_t from cache with given TTL.
 * Return the number of bytes consumed or an error code.
 */
static int rdataset_materialize(knot_rdataset_t * restrict rds, const uint8_t * const data,
				const uint8_t *data_bound, knot_mm_t *pool)
{
	assert(rds && data && data_bound && data_bound > data && !rds->rdata
		/*&& !((size_t)data & 1)*/);
	assert(pool); /* not required, but that's our current usage; guard leaks */
	const uint8_t *d = data; /* iterates over the cache data */
	/* First sum up the sizes for wire format length. */
	/* TODO: we might overrun here already, but we need to trust cache anyway...*/
	const uint32_t rds_size = rdataset_dematerialized_size(d, &rds->count);
	d += KR_CACHE_RR_COUNT_SIZE;
	#if KNOT_VERSION_HEX >= 0x020900
		rds->size = rds_size;
	#endif
	if (d + rds_size > data_bound) {
		VERBOSE_MSG(NULL, "materialize: EILSEQ!\n");
		return kr_error(EILSEQ);
	}
	if (!rds->count) { /* avoid mm_alloc(pool, 0); etc. */
		rds->rdata = NULL;
		return d - data;
	}
	rds->rdata = mm_alloc(pool, rds_size);
	if (!rds->rdata) {
		return kr_error(ENOMEM);
	}
	memcpy(rds->rdata, d, rds_size);
	d += rds_size;
	//VERBOSE_MSG(NULL, "materialized from %d B\n", (int)(d - data));
	return d - data;
}

int kr_cache_materialize(knot_rdataset_t *dst, const struct kr_cache_p *ref,
			 knot_mm_t *pool)
{
	struct entry_h *eh = ref->raw_data;
	return rdataset_materialize(dst, eh->data, ref->raw_bound, pool);
}


int entry2answer(struct answer *ans, int id,
		const struct entry_h *eh, const uint8_t *eh_bound,
		const knot_dname_t *owner, uint16_t type, uint32_t new_ttl)
{
	/* We assume it's zeroed.  Do basic sanity check. */
	if (ans->rrsets[id].set.rr || ans->rrsets[id].sig_rds.rdata
	    || (type == KNOT_RRTYPE_NSEC  &&  ans->nsec_p.raw)
	    || (type == KNOT_RRTYPE_NSEC3 && !ans->nsec_p.raw)
	   )
	{
		assert(false);
		return kr_error(EINVAL);
	}
	/* Materialize the base RRset. */
	knot_rrset_t *rr = ans->rrsets[id].set.rr
		= knot_rrset_new(owner, type, KNOT_CLASS_IN, new_ttl, ans->mm);
	if (!rr) {
		assert(!ENOMEM);
		return kr_error(ENOMEM);
	}
	int ret = rdataset_materialize(&rr->rrs, eh->data, eh_bound, ans->mm);
	if (ret < 0) goto fail;
	size_t data_off = ret;
	ans->rrsets[id].set.rank = eh->rank;
	ans->rrsets[id].set.expiring = is_expiring(eh->ttl, new_ttl);
	/* Materialize the RRSIG RRset for the answer in (pseudo-)packet. */
	bool want_rrsigs = true; /* LATER(optim.): might be omitted in some cases. */
	if (want_rrsigs) {
		ret = rdataset_materialize(&ans->rrsets[id].sig_rds, eh->data + data_off,
					   eh_bound, ans->mm);
		if (ret < 0) goto fail;
		/* Sanity check: we consumed exactly all data. */
		int unused_bytes = eh_bound - (uint8_t *)eh->data - data_off - ret;
		if (unused_bytes) {
			kr_log_error("[cach] entry2answer ERROR: unused bytes: %d\n",
					unused_bytes);
			assert(!EILSEQ);
			ret = kr_error(EILSEQ);
			goto fail; /* to be on the safe side */
		}
	}
	return kr_ok();
fail:
	assert(/*false*/!ret);
	/* Cleanup the item that we might've (partially) written to. */
	knot_rrset_free(ans->rrsets[id].set.rr, ans->mm);
	knot_rdataset_clear(&ans->rrsets[id].sig_rds, ans->mm);
	memset(&ans->rrsets[id], 0, sizeof(ans->rrsets[id]));
	return kr_error(ret);
}

