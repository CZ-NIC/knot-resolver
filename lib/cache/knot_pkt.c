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
 * Implementation of preparing knot_pkt_t for filling with RRs.
 * Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"

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
static int pkt_alloc_space(knot_pkt_t *pkt, int count)
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
		*rr_rank = (i == 0) ? rank : (KR_RANK_OMIT | KR_RANK_AUTH);
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

