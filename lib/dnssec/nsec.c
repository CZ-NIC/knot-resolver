/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/nsec.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/defines.h"
#include "lib/dnssec/nsec.h"

int kr_nsec_nomatch_validate(const knot_rrset_t *nsec, const knot_dname_t *name)
{
	const knot_dname_t *next = knot_nsec_next(&nsec->rrs);

	if ((knot_dname_cmp(nsec->owner, name) < 0) &&
	    (knot_dname_cmp(name, next) < 0)) {
		return kr_ok();
	} else {
		return 1;
	}

#warning TODO: Is an additional request for NSEC name or wildcard necessary?
}

#define FLG_NOEXIST_RRTYPE 0x01 /**< RR type has been proven not to exist. */
#define FLG_NOEXIST_RRSET  0x02 /**< RRSet has been proven not to exist. */
#define FLG_NOEXIST_WILDCARD 0x03 /**< No cowering wildcard exists. */

/**
 * Checks whether the given type exists in the supplied NSEC bitmap.
 * @param nsec NSEC RR.
 * @param type Type to search for.
 */
bool nsec_bitmap_has_type(const knot_rrset_t *nsec, uint16_t type)
{
	if (!nsec) {
		return false;
	}

	uint8_t *bm;
	uint16_t bm_size;
	knot_nsec_bitmap(&nsec->rrs, &bm, &bm_size);
	if (!bm) {
		return false;
	}

	uint8_t sought_win = (type >> 8 ) & 0xff;
	uint8_t bitmap_idx = (type >> 3) & 0x1f;
	uint8_t bitmap_bit_mask = 1 << (7 - (type & 0x07));

	size_t bm_pos = 0;
	while (bm_pos < bm_size) {
		uint8_t win = bm[bm_pos++];
		uint8_t win_size = bm[bm_pos++];

		if (win == sought_win) {
			if (win_size >= bitmap_idx) {
				return bm[bm_pos + bitmap_idx] & bitmap_bit_mask;
			}
			return false;
		}

		bm_pos += win_size;
	}

	return false;
}

/**
 * Returns the labels from the covering RRSIG RRs.
 * @note The number must be the same in all covering RRSIGs.
 * @param nsec NSEC RR.
 * @param sec  Packet section.
 * @param      Number of labels or (negative) error code.
 */
static int coverign_rrsig_labels(const knot_rrset_t *nsec, const knot_pktsection_t *sec)
{
	assert(nsec && sec);

	int ret = kr_error(ENOENT);

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if ((rrset->type != KNOT_RRTYPE_RRSIG) ||
		    (!knot_dname_is_equal(rrset->owner, nsec->owner))) {
			continue;
		}

		for (uint16_t j = 0; j < rrset->rrs.rr_count; ++j) {
			if (knot_rrsig_type_covered(&rrset->rrs, j) != KNOT_RRTYPE_NSEC) {
				continue;
			}

			if (ret < 0) {
				ret = knot_rrsig_labels(&rrset->rrs, j);
			} else {
				if (ret != knot_rrsig_labels(&rrset->rrs, j)) {
					return kr_error(EINVAL);
				}
			}
		}
	}

	return ret;
}

/**
 * Perform check of RR type existence denial according to RFC4035 5.4, bullet 1.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param sec   Packet section to work with.
 * @param type  Type to be checked.
 */
static int rr_type_existence_denial(int *flags, const knot_rrset_t *nsec,
                                    const knot_pktsection_t *sec, uint16_t type)
{
	assert(flags && nsec && sec);

	if (nsec_bitmap_has_type(nsec, type)) {
		return kr_ok();
	}
	/* The type is not listed in the NSEC bitmap. */
	*flags |= FLG_NOEXIST_RRTYPE;

	int rrsig_labels = coverign_rrsig_labels(nsec, sec);
	if (rrsig_labels < 0) {
		return rrsig_labels;
	}
	int nsec_labels = knot_dname_labels(nsec->owner, NULL);
	if (nsec_labels < 0) {
		return nsec_labels;
	}

	if (rrsig_labels == nsec_labels) {
		*flags |= FLG_NOEXIST_WILDCARD;
	}

	return kr_ok();
}

/**
 * Perform check of RRSet existence denial according to RFC4035 5.4, bullet 2.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param name  Name to be checked.
 * @param pool
 * @return      0 or error code.
 */
static int rrset_existence_denial(int *flags, const knot_rrset_t *nsec,
                                  const knot_dname_t *name, mm_ctx_t *pool)
{
	assert(flags && nsec && name);

	if (kr_nsec_nomatch_validate(nsec, name) == 0) {
		*flags |= FLG_NOEXIST_RRSET;
		return kr_ok();
	}

	if (!pool) {
		return kr_error(EINVAL);
	}

	knot_dname_t *name_copy = knot_dname_copy(name, pool);
	if (!name_copy) {
		return kr_error(ENOMEM);
	}
	knot_dname_t *ptr = name_copy;
	while (ptr[0]) {
		/* Remove leftmost label and replace it with '*.'. */
		ptr = (uint8_t *) knot_wire_next_label(ptr, NULL);
		*(--ptr) = '*';
		*(--ptr) = 1;

		if (kr_nsec_nomatch_validate(nsec, ptr) == 0) {
			*flags |= FLG_NOEXIST_WILDCARD;
			break;
		}

		/* Remove added leftmost asterisk. */
		ptr += 2;
	}

	knot_dname_free(&name_copy, pool);
	return kr_ok();
}

int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *name, uint16_t type, mm_ctx_t *pool)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec) {
		return kr_error(EINVAL);
	}

	int ret = kr_error(ENOENT);
	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		if (knot_dname_is_equal(rrset->owner, name)) {
			rr_type_existence_denial(&flags, rrset, sec, type);
		} else {
			rrset_existence_denial(&flags, rrset, name, pool);
		}
	}

	if (((flags & FLG_NOEXIST_RRTYPE) || (flags & FLG_NOEXIST_RRSET)) &&
	    (flags & FLG_NOEXIST_WILDCARD)) {
		ret = kr_ok();
	}

	return ret;
}
