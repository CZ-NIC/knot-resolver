/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdlib.h>

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/packet/wire.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/nsec.h>
#include <libknot/rrtype/rrsig.h>
#include <libdnssec/error.h>
#include <libdnssec/nsec.h>

#include "lib/defines.h"
#include "lib/dnssec/nsec.h"
#include "lib/utils.h"


int kr_nsec_children_in_zone_check(const uint8_t *bm, uint16_t bm_size)
{
	if (!bm)
		return kr_error(EINVAL);
	const bool parent_side =
		dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_DNAME)
		|| (dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_NS)
		    && !dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_SOA)
		);
	return parent_side ? abs(ENOENT) : kr_ok();
	/* LATER: after refactoring, probably also check if signer name equals owner,
	 * but even without that it's not possible to attack *correctly* signed zones.
	 */
}

/* This block of functions implements a "safe" version of knot_dname_cmp(),
 * until that one handles in-label zero bytes correctly. */
static int lf_cmp(const uint8_t *lf1, const uint8_t *lf2)
{
	/* Compare common part. */
	uint8_t common = lf1[0];
	if (common > lf2[0]) {
		common = lf2[0];
	}
	int ret = memcmp(lf1 + 1, lf2 + 1, common);
	if (ret != 0) {
		return ret;
	}

	/* If they match, compare lengths. */
	if (lf1[0] < lf2[0]) {
		return -1;
	} else if (lf1[0] > lf2[0]) {
		return 1;
	} else {
		return 0;
	}
}
static void dname_reverse(const knot_dname_t *src, size_t src_len, knot_dname_t *dst)
{
	knot_dname_t *idx = dst + src_len - 1;
	kr_require(src[src_len - 1] == '\0');
	*idx = '\0';

	while (*src) {
		uint16_t len = *src + 1;
		idx -= len;
		memcpy(idx, src, len);
		src += len;
	}
	kr_require(idx == dst);
}
static int dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2)
{
	size_t d1_len = knot_dname_size(d1);
	size_t d2_len = knot_dname_size(d2);

	knot_dname_t d1_rev_arr[d1_len], d2_rev_arr[d2_len];
	const knot_dname_t *d1_rev = d1_rev_arr, *d2_rev = d2_rev_arr;

	dname_reverse(d1, d1_len, d1_rev_arr);
	dname_reverse(d2, d2_len, d2_rev_arr);

	int res = 0;
	while (res == 0 && d1_rev != NULL) {
		res = lf_cmp(d1_rev, d2_rev);
		d1_rev = knot_wire_next_label(d1_rev, NULL);
		d2_rev = knot_wire_next_label(d2_rev, NULL);
	}

	kr_require(res != 0 || d2_rev == NULL);
	return res;
}


/**
 * Check whether the NSEC RR proves that there is no closer match for <SNAME, SCLASS>.
 * @param nsec  NSEC RRSet.
 * @param sname Searched name.
 * @return      0 if proves, >0 if not (abs(ENOENT)), or error code (<0).
 */
static int nsec_covers(const knot_rrset_t *nsec, const knot_dname_t *sname)
{
	if (kr_fails_assert(nsec && sname))
		return kr_error(EINVAL);
	if (dname_cmp(sname, nsec->owner) <= 0)
		return abs(ENOENT); /* 'sname' before 'owner', so can't be covered */

	/* If NSEC 'owner' >= 'next', it means that there is nothing after 'owner' */
	/* We have to lower-case it with libknot >= 2.7; see also RFC 6840 5.1. */
	knot_dname_t next[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire(next, knot_nsec_next(nsec->rrs.rdata), sizeof(next));
	if (kr_fails_assert(ret >= 0))
		return kr_error(ret);
	knot_dname_to_lower(next);

	const bool is_last_nsec = dname_cmp(nsec->owner, next) >= 0;
	const bool in_range = is_last_nsec || dname_cmp(sname, next) < 0;
	if (!in_range)
		return abs(ENOENT);
	/* Before returning kr_ok(), we have to check a special case:
	 * sname might be under delegation from owner and thus
	 * not in the zone of this NSEC at all.
	 */
	if (knot_dname_in_bailiwick(sname, nsec->owner) <= 0)
		return kr_ok();
	const uint8_t *bm = knot_nsec_bitmap(nsec->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(nsec->rrs.rdata);

	return kr_nsec_children_in_zone_check(bm, bm_size);
}

#define FLG_NOEXIST_RRTYPE (1 << 0) /**< <SNAME, SCLASS> exists, <SNAME, SCLASS, STYPE> does not exist. */
#define FLG_NOEXIST_RRSET  (1 << 1) /**< <SNAME, SCLASS> does not exist. */
#define FLG_NOEXIST_WILDCARD (1 << 2) /**< No wildcard covering <SNAME, SCLASS> exists. */
#define FLG_NOEXIST_CLOSER (1 << 3) /**< Wildcard covering <SNAME, SCLASS> exists, but doesn't match STYPE. */


/**
 * According to set flags determine whether NSEC proving
 * RRset or RRType non-existence has been found.
 * @param f Flags to inspect.
 * @return  True if required NSEC exists.
 */
#define kr_nsec_rrset_noexist(f) \
        ((f) & (FLG_NOEXIST_RRTYPE | FLG_NOEXIST_RRSET))
/**
 * According to set flags determine whether wildcard non-existence
 * has been proven.
 * @param f Flags to inspect.
 * @return  True if wildcard not exists.
 */
#define kr_nsec_wcard_noexist(f) ((f) & FLG_NOEXIST_WILDCARD)

/**
 * According to set flags determine whether authenticated denial of existence has been proven.
 * @param f Flags to inspect.
 * @return  True if denial of existence proven.
 */
#define kr_nsec_existence_denied(f) \
	((kr_nsec_rrset_noexist(f)) && (kr_nsec_wcard_noexist(f)))

/**
 * Name error response check (RFC4035 3.1.3.2; RFC4035 5.4, bullet 2).
 * @note Returned flags must be checked in order to prove denial.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param name  Name to be checked.
 * @param pool
 * @return      0 or error code.
 */
static int name_error_response_check_rr(int *flags, const knot_rrset_t *nsec,
                                        const knot_dname_t *name)
{
	if (kr_fails_assert(flags && nsec && name))
		return kr_error(EINVAL);

	if (nsec_covers(nsec, name) == 0)
		*flags |= FLG_NOEXIST_RRSET;

	/* Try to find parent wildcard that is proved by this NSEC. */
	uint8_t namebuf[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire(namebuf, name, sizeof(namebuf));
	if (ret < 0)
		return ret;
	knot_dname_t *ptr = namebuf;
	while (ptr[0]) {
		/* Remove leftmost label and replace it with '\1*'. */
		ptr = (uint8_t *) knot_wire_next_label(ptr, NULL);
		if (!ptr)
			return kr_error(EINVAL);
		*(--ptr) = '*';
		*(--ptr) = 1;
		/* True if this wildcard provably doesn't exist. */
		if (nsec_covers(nsec, ptr) == 0) {
			*flags |= FLG_NOEXIST_WILDCARD;
			break;
		}
		/* Remove added leftmost asterisk. */
		ptr += 2;
	}

	return kr_ok();
}

int kr_nsec_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                      const knot_dname_t *sname)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC)
			continue;
		int ret = name_error_response_check_rr(&flags, rrset, sname);
		if (ret != 0)
			return ret;
	}

	return kr_nsec_existence_denied(flags) ? kr_ok() : kr_error(ENOENT);
}

/**
 * Returns the labels from the covering RRSIG RRs.
 * @note The number must be the same in all covering RRSIGs.
 * @param nsec NSEC RR.
 * @param sec  Packet section.
 * @param      Number of labels or (negative) error code.
 */
static int covering_rrsig_labels(const knot_rrset_t *nsec, const knot_pktsection_t *sec)
{
	if (kr_fails_assert(nsec && sec))
		return kr_error(EINVAL);

	int ret = kr_error(ENOENT);

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if ((rrset->type != KNOT_RRTYPE_RRSIG) ||
		    (!knot_dname_is_equal(rrset->owner, nsec->owner))) {
			continue;
		}

		knot_rdata_t *rdata_j = rrset->rrs.rdata;
		for (uint16_t j = 0; j < rrset->rrs.count;
				++j, rdata_j = knot_rdataset_next(rdata_j)) {
			if (knot_rrsig_type_covered(rdata_j) != KNOT_RRTYPE_NSEC)
				continue;

			if (ret < 0) {
				ret = knot_rrsig_labels(rdata_j);
			} else {
				if (ret != knot_rrsig_labels(rdata_j)) {
					return kr_error(EINVAL);
				}
			}
		}
	}

	return ret;
}


int kr_nsec_bitmap_nodata_check(const uint8_t *bm, uint16_t bm_size, uint16_t type, const knot_dname_t *owner)
{
	const int NO_PROOF = abs(ENOENT);
	if (!bm || !owner)
		return kr_error(EINVAL);
	if (dnssec_nsec_bitmap_contains(bm, bm_size, type))
		return NO_PROOF;

	if (type != KNOT_RRTYPE_CNAME
	    && dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_CNAME)) {
		return NO_PROOF;
	}
	/* Special behavior around zone cuts. */
	switch (type) {
	case KNOT_RRTYPE_DS:
		/* Security feature: in case of DS also check for SOA
		 * non-existence to be more certain that we don't hold
		 * a child-side NSEC by some mistake (e.g. when forwarding).
		 * See RFC4035 5.2, next-to-last paragraph.
		 * This doesn't apply for root DS as it doesn't exist in DNS hierarchy.
		 */
		if (owner[0] != '\0' && dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_SOA))
			return NO_PROOF;
		break;
	case KNOT_RRTYPE_CNAME:
		/* Exception from the `default` rule.  It's perhaps disputable,
		 * but existence of CNAME at zone apex is not allowed, so we
		 * consider a parent-side record to be enough to prove non-existence. */
		break;
	default:
		/* Parent-side delegation record isn't authoritative for non-DS;
		 * see RFC6840 4.1. */
		if (dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_NS)
		    && !dnssec_nsec_bitmap_contains(bm, bm_size, KNOT_RRTYPE_SOA)) {
			return NO_PROOF;
		}
		/* LATER(opt): perhaps short-circuit test if we repeat it here. */
	}

	return kr_ok();
}

/**
 * Attempt to prove NODATA given a matching NSEC.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param type  Type to be checked.
 * @return      0 on success, abs(ENOENT) for no proof, or error code (<0).
 * @note        It's not a *full* proof, of course (wildcards, etc.)
 * @TODO returning result via `flags` is just ugly.
 */
static int no_data_response_check_rrtype(int *flags, const knot_rrset_t *nsec,
                                         uint16_t type)
{
	if (kr_fails_assert(flags && nsec))
		return kr_error(EINVAL);

	const uint8_t *bm = knot_nsec_bitmap(nsec->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(nsec->rrs.rdata);
	int ret = kr_nsec_bitmap_nodata_check(bm, bm_size, type, nsec->owner);
	if (ret == kr_ok())
		*flags |= FLG_NOEXIST_RRTYPE;
	return ret <= 0 ? ret : kr_ok();
}

/**
 * Perform check for RR type wildcard existence denial according to RFC4035 5.4, bullet 1.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param sec   Packet section to work with.
 * @return      0 or error code.
 */
static int no_data_wildcard_existence_check(int *flags, const knot_rrset_t *nsec,
                                            const knot_pktsection_t *sec)
{
	if (kr_fails_assert(flags && nsec && sec))
		return kr_error(EINVAL);

	int rrsig_labels = covering_rrsig_labels(nsec, sec);
	if (rrsig_labels < 0)
		return rrsig_labels;
	int nsec_labels = knot_dname_labels(nsec->owner, NULL);
	if (nsec_labels < 0)
		return nsec_labels;

	if (rrsig_labels == nsec_labels)
		*flags |= FLG_NOEXIST_WILDCARD;

	return kr_ok();
}

/**
 * Perform check for NSEC wildcard existence that covers sname and
 * have no stype bit set.
 * @param pkt   Packet structure to be processed.
 * @param sec   Packet section to work with.
 * @param sname Queried domain name.
 * @param stype Queried type.
 * @return      0 or error code.
 */
static int wildcard_match_check(const knot_pkt_t *pkt, const knot_pktsection_t *sec,
				const knot_dname_t *sname, uint16_t stype)
{
	if (!sec || !sname)
		return kr_error(EINVAL);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC)
			continue;
		if (!knot_dname_is_wildcard(rrset->owner))
			continue;
		if (!knot_dname_is_equal(rrset->owner, sname)) {
			int wcard_labels = knot_dname_labels(rrset->owner, NULL);
			int common_labels = knot_dname_matched_labels(rrset->owner, sname);
			int rrsig_labels = covering_rrsig_labels(rrset, sec);
			if (wcard_labels < 1 ||
			    common_labels != wcard_labels - 1 ||
			    common_labels != rrsig_labels) {
				continue;
			}
		}
		int ret = no_data_response_check_rrtype(&flags, rrset, stype);
		if (ret != 0)
			return ret;
	}
	return (flags & FLG_NOEXIST_RRTYPE) ? kr_ok() : kr_error(ENOENT);
}

int kr_nsec_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                   const knot_dname_t *sname, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC)
			continue;
		if (knot_dname_is_equal(rrset->owner, sname)) {
			int ret = no_data_response_check_rrtype(&flags, rrset, stype);
			if (ret != 0)
				return ret;
		}
	}

	return (flags & FLG_NOEXIST_RRTYPE) ? kr_ok() : kr_error(ENOENT);
}

int kr_nsec_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                           const knot_dname_t *sname)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC)
			continue;
		if (nsec_covers(rrset, sname) == 0)
			return kr_ok();
	}

	return kr_error(ENOENT);
}

int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *sname, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC)
			continue;
		/* NSEC proves that name exists, but has no data (RFC4035 4.9, 1) */
		if (knot_dname_is_equal(rrset->owner, sname)) {
			no_data_response_check_rrtype(&flags, rrset, stype);
		} else {
			/* NSEC proves that name doesn't exist (RFC4035, 4.9, 2) */
			name_error_response_check_rr(&flags, rrset, sname);
		}
		no_data_wildcard_existence_check(&flags, rrset, sec);
	}
	if (kr_nsec_existence_denied(flags)) {
		/* denial of existence proved accordingly to 4035 5.4 -
		 * NSEC proving either rrset non-existence or
		 * qtype non-existence has been found,
		 * and no wildcard expansion occurred.
		 */
		return kr_ok();
	} else if (kr_nsec_rrset_noexist(flags)) {
		/* NSEC proving either rrset non-existence or
		 * qtype non-existence has been found,
		 * but wildcard expansion occurs.
		 * Try to find matching wildcard and check
		 * corresponding types.
		 */
		return wildcard_match_check(pkt, sec, sname, stype);
	}
	return kr_error(ENOENT);
}

int kr_nsec_ref_to_unsigned(const knot_pkt_t *pkt)
{
	int nsec_found = 0;
	const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_AUTHORITY);
	if (!sec)
		return kr_error(EINVAL);
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *ns = knot_pkt_rr(sec, i);
		if (ns->type == KNOT_RRTYPE_DS)
			return kr_error(EEXIST);
		if (ns->type != KNOT_RRTYPE_NS)
			continue;
		nsec_found = 0;
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *nsec = knot_pkt_rr(sec, j);
			if (nsec->type == KNOT_RRTYPE_DS)
				return kr_error(EEXIST);
			if (nsec->type != KNOT_RRTYPE_NSEC)
				continue;
			/* nsec found
			 * check if owner name matches the delegation name
			 */
			if (!knot_dname_is_equal(nsec->owner, ns->owner)) {
				/* nsec does not match the delegation */
				continue;
			}
			nsec_found = 1;
			const uint8_t *bm = knot_nsec_bitmap(nsec->rrs.rdata);
			uint16_t bm_size = knot_nsec_bitmap_len(nsec->rrs.rdata);
			if (!bm)
				return kr_error(EINVAL);
			if (dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_NS) &&
			    !dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_DS) &&
			    !dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_SOA)) {
				/* rfc4035, 5.2 */
				return kr_ok();
			}
		}
		if (nsec_found) {
			/* nsec which owner matches
			 * the delegation name was found,
			 * but nsec type bitmap contains wrong types
			 */
			return kr_error(EINVAL);
		} else {
			/* nsec that matches delegation was not found */
			return kr_error(DNSSEC_NOT_FOUND);
		}
	}

	return kr_error(EINVAL);
}

int kr_nsec_matches_name_and_type(const knot_rrset_t *nsec,
				   const knot_dname_t *name, uint16_t type)
{
	/* It's not secure enough to just check a single bit for (some) other types,
	 * but we don't (currently) only use this API for NS.  See RFC 6840 sec. 4.
	 */
	if (kr_fails_assert(type == KNOT_RRTYPE_NS && nsec && name))
		return kr_error(EINVAL);
	if (!knot_dname_is_equal(nsec->owner, name))
		return kr_error(ENOENT);
	const uint8_t *bm = knot_nsec_bitmap(nsec->rrs.rdata);
	uint16_t bm_size = knot_nsec_bitmap_len(nsec->rrs.rdata);
	if (!bm)
		return kr_error(EINVAL);
	if (dnssec_nsec_bitmap_contains(bm, bm_size, type)) {
		return kr_ok();
	} else {
		return kr_error(ENOENT);
	}
}
