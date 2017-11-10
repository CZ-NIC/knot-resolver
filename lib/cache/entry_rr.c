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
 * Implementation of RRset (de)materialization, i.e. (de)serialization to storage
 * format used in cache (some repeated fields are omitted).  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"

int rdataset_dematerialize(const knot_rdataset_t *rds, void * restrict data)
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
	//VERBOSE_MSG(NULL, "materialized from %d B\n", (int)(d - data));
	return d - data;
}

int kr_cache_materialize(knot_rdataset_t *dst, const struct kr_cache_p *ref,
			 uint32_t new_ttl, knot_mm_t *pool)
{
	struct entry_h *eh = ref->raw_data;
	return rdataset_materialize(dst, eh->data, ref->raw_bound, new_ttl, pool);
}


int entry2answer(struct answer *ans, int id,
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

