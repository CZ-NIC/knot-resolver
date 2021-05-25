/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>

#include <libdnssec/binary.h>
#include <libdnssec/error.h>
#include <libdnssec/nsec.h>
#include <libknot/descriptor.h>
#include <contrib/base32hex.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/nsec3.h>

#include "lib/defines.h"
#include "lib/dnssec/nsec.h"
#include "lib/dnssec/nsec3.h"
#include "lib/utils.h"

#define OPT_OUT_BIT 0x01

//#define FLG_CLOSEST_ENCLOSER (1 << 0)
#define FLG_CLOSEST_PROVABLE_ENCLOSER (1 << 1)
#define FLG_NAME_COVERED (1 << 2)
#define FLG_NAME_MATCHED (1 << 3)
#define FLG_TYPE_BIT_MISSING (1 << 4)
#define FLG_CNAME_BIT_MISSING (1 << 5)

/**
 * Obtains NSEC3 parameters from RR.
 * @param params NSEC3 parameters structure to be set.
 * @param nsec3  NSEC3 RR containing the parameters.
 * @return       0 or error code.
 */
static int nsec3_parameters(dnssec_nsec3_params_t *params, const knot_rrset_t *nsec3)
{
	if (kr_fails_assert(params && nsec3))
		return kr_error(EINVAL);

	const knot_rdata_t *rr = knot_rdataset_at(&nsec3->rrs, 0);
	if (kr_fails_assert(rr))
		return kr_error(EINVAL);

	/* Every NSEC3 RR contains data from NSEC3PARAMS. */
	const size_t SALT_OFFSET = 5; /* First 5 octets contain { Alg, Flags, Iterations, Salt length } */
	dnssec_binary_t rdata = {
		.size = SALT_OFFSET + (size_t)knot_nsec3_salt_len(nsec3->rrs.rdata),
		.data = /*const-cast*/(uint8_t *)rr->data,
	};
	if (rdata.size > rr->len)
		return kr_error(EMSGSIZE);

	int ret = dnssec_nsec3_params_from_rdata(params, &rdata);
	if (ret != DNSSEC_EOK)
		return kr_error(EINVAL);

	return kr_ok();
}

/**
 * Computes a hash of a given domain name.
 * @param hash   Resulting hash, must be freed.
 * @param params NSEC3 parameters.
 * @param name   Domain name to be hashed.
 * @return       0 or error code.
 */
static int hash_name(dnssec_binary_t *hash, const dnssec_nsec3_params_t *params,
                     const knot_dname_t *name)
{
	if (kr_fails_assert(hash && params))
		return kr_error(EINVAL);
	if (!name)
		return kr_error(EINVAL);
	if (kr_fails_assert(params->iterations <= KR_NSEC3_MAX_ITERATIONS)) {
		/* This if is mainly defensive; it shouldn't happen. */
		return kr_error(EINVAL);
	}

	dnssec_binary_t dname = {
		.size = knot_dname_size(name),
		.data = (uint8_t *) name,
	};

	int ret = dnssec_nsec3_hash(&dname, params, hash);
	if (ret != DNSSEC_EOK) {
		return kr_error(EINVAL);
	}

	return kr_ok();
}

/**
 * Read hash from NSEC3 owner name and store its binary form.
 * @param hash          Buffer to be written.
 * @param max_hash_size Maximal has size.
 * @param nsec3         NSEC3 RR.
 * @return              0 or error code.
 */
static int read_owner_hash(dnssec_binary_t *hash, size_t max_hash_size, const knot_rrset_t *nsec3)
{
	if (kr_fails_assert(hash && nsec3 && hash->data))
		return kr_error(EINVAL);

	int32_t ret = base32hex_decode(nsec3->owner + 1, nsec3->owner[0], hash->data, max_hash_size);
	if (ret < 0)
		return kr_error(EILSEQ);
	hash->size = ret;

	return kr_ok();
}

#define MAX_HASH_BYTES 64
/**
 * Closest (provable) encloser match (RFC5155 7.2.1, bullet 1).
 * @param flags   Flags to be set according to check outcome.
 * @param nsec3   NSEC3 RR.
 * @param name    Name to be checked.
 * @param skipped Number of skipped labels to find closest (provable) match.
 * @return        0 or error code.
 */
static int closest_encloser_match(int *flags, const knot_rrset_t *nsec3,
                                  const knot_dname_t *name, unsigned *skipped)
{
	if (kr_fails_assert(flags && nsec3 && name && skipped))
		return kr_error(EINVAL);

	uint8_t hash_data[MAX_HASH_BYTES] = {0, };
	dnssec_binary_t owner_hash = { 0, hash_data };
	dnssec_nsec3_params_t params = { 0, };
	dnssec_binary_t name_hash = { 0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0)
		goto fail;

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0)
		goto fail;

	/* Root label has no encloser */
	if (!name[0]) {
		ret = kr_error(ENOENT);
		goto fail;
	}

	const knot_dname_t *encloser = knot_wire_next_label(name, NULL);
	*skipped = 1;

	while(encloser) {
		ret = hash_name(&name_hash, &params, encloser);
		if (ret != 0)
			goto fail;

		if ((owner_hash.size == name_hash.size) &&
		    (memcmp(owner_hash.data, name_hash.data, owner_hash.size) == 0)) {
			dnssec_binary_free(&name_hash);
			*flags |= FLG_CLOSEST_PROVABLE_ENCLOSER;
			break;
		}

		dnssec_binary_free(&name_hash);

		if (!encloser[0])
			break;
		encloser = knot_wire_next_label(encloser, NULL);
		++(*skipped);
	}

	ret = kr_ok();

fail:
	if (params.salt.data)
		dnssec_nsec3_params_free(&params);
	if (name_hash.data)
		dnssec_binary_free(&name_hash);
	return ret;
}

/**
 * Checks whether NSEC3 RR covers the supplied name (RFC5155 7.2.1, bullet 2).
 * @param flags Flags to be set according to check outcome.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @return      0 or error code.
 */
static int covers_name(int *flags, const knot_rrset_t *nsec3, const knot_dname_t *name)
{
	if (kr_fails_assert(flags && nsec3 && name))
		return kr_error(EINVAL);

	uint8_t hash_data[MAX_HASH_BYTES] = { 0, };
	dnssec_binary_t owner_hash = { 0, hash_data };
	dnssec_nsec3_params_t params = { 0, };
	dnssec_binary_t name_hash = { 0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0)
		goto fail;

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0)
		goto fail;

	ret = hash_name(&name_hash, &params, name);
	if (ret != 0)
		goto fail;

	uint8_t next_size = knot_nsec3_next_len(nsec3->rrs.rdata);
	const uint8_t *next_hash = knot_nsec3_next(nsec3->rrs.rdata);

	if ((next_size > 0) && (owner_hash.size == next_size) && (name_hash.size == next_size)) {
		/* All hash lengths must be same. */
		const uint8_t *ownrd = owner_hash.data;
		const uint8_t *nextd = next_hash;
		int covered = 0;
		int greater_then_owner = (memcmp(ownrd, name_hash.data, next_size) < 0);
		int less_then_next = (memcmp(name_hash.data, nextd, next_size) < 0);
		if (memcmp(ownrd, nextd, next_size) < 0) {
			/*
			 * 0 (...) owner ... next (...) MAX
			 *                ^
			 *                name
			 * ==>
			 * (owner < name) && (name < next)
			 */
			covered = ((greater_then_owner) && (less_then_next));
		} else {
			/*
			 * owner ... MAX, 0 ... next
			 *        ^     ^    ^
			 *        name  name name
			 * =>
			 * (owner < name) || (name < next)
			 */
			covered = ((greater_then_owner) || (less_then_next));
		}

		if (covered) {
			*flags |= FLG_NAME_COVERED;

			uint8_t nsec3_flags = knot_nsec3_flags(nsec3->rrs.rdata);
			if (nsec3_flags & ~OPT_OUT_BIT) {
				/* RFC5155 3.1.2 */
				ret = kr_error(EINVAL);
			} else {
				ret = kr_ok();
			}
		}
	}

fail:
	if (params.salt.data)
		dnssec_nsec3_params_free(&params);
	if (name_hash.data)
		dnssec_binary_free(&name_hash);
	return ret;
}

/**
 * Checks whether NSEC3 RR has the opt-out bit set.
 * @param flags Flags to be set according to check outcome.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @return      0 or error code.
 */
static bool has_optout(const knot_rrset_t *nsec3)
{
	if (!nsec3)
		return false;

	uint8_t nsec3_flags = knot_nsec3_flags(nsec3->rrs.rdata);
	if (nsec3_flags & ~OPT_OUT_BIT) {
		/* RFC5155 3.1.2 */
		return false;
	}

	return nsec3_flags & OPT_OUT_BIT;
}

/**
 * Checks whether NSEC3 RR matches the supplied name.
 * @param flags Flags to be set according to check outcome.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @return      0 if matching, >0 if not (abs(ENOENT)), or error code (<0).
 */
static int matches_name(const knot_rrset_t *nsec3, const knot_dname_t *name)
{
	if (kr_fails_assert(nsec3 && name))
		return kr_error(EINVAL);

	uint8_t hash_data[MAX_HASH_BYTES] = { 0, };
	dnssec_binary_t owner_hash = { 0, hash_data };
	dnssec_nsec3_params_t params = { 0, };
	dnssec_binary_t name_hash = { 0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0)
		goto fail;

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0)
		goto fail;

	ret = hash_name(&name_hash, &params, name);
	if (ret != 0)
		goto fail;

	if ((owner_hash.size == name_hash.size) &&
	    (memcmp(owner_hash.data, name_hash.data, owner_hash.size) == 0)) {
		ret = kr_ok();
	} else {
		ret = abs(ENOENT);
	}

fail:
	if (params.salt.data)
		dnssec_nsec3_params_free(&params);
	if (name_hash.data)
		dnssec_binary_free(&name_hash);
	return ret;
}
#undef MAX_HASH_BYTES

/**
 * Prepends an asterisk label to given name.
 *
 * @param tgt  Target buffer to write domain name into.
 * @param name Name to be added to the asterisk.
 * @return     Size of the resulting name or error code.
 */
static int prepend_asterisk(uint8_t *tgt, size_t maxlen, const knot_dname_t *name)
{
	if (kr_fails_assert(maxlen >= 3))
		return kr_error(EINVAL);
	memcpy(tgt, "\1*", 3);
	return knot_dname_to_wire(tgt + 2, name, maxlen - 2);
}

/**
 * Closest encloser proof (RFC5155 7.2.1).
 * @note No RRSIGs are validated.
 * @param pkt                     Packet structure to be processed.
 * @param section_id              Packet section to be processed.
 * @param sname                   Name to be checked.
 * @param encloser_name           Returned matching encloser name, if found.
 * @param matching_encloser_nsec3 Pointer to matching encloser NSEC RRSet.
 * @param covering_next_nsec3     Pointer to covering next closer NSEC3 RRSet.
 * @return                        0 or error code.
 */
static int closest_encloser_proof(const knot_pkt_t *pkt,
				  knot_section_t section_id,
				  const knot_dname_t *sname,
				  const knot_dname_t **encloser_name,
				  const knot_rrset_t **matching_encloser_nsec3,
				  const knot_rrset_t **covering_next_nsec3)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	const knot_rrset_t *matching = NULL;
	const knot_rrset_t *covering = NULL;

	int flags = 0;
	const knot_dname_t *next_closer = NULL;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3)
			continue;
		/* Also skip the NSEC3-to-match an ancestor of sname if it's
		 * a parent-side delegation, as that would mean the owner
		 * does not really exist (authoritatively in this zone,
		 * even in case of opt-out).
		 */
		const uint8_t *bm = knot_nsec3_bitmap(rrset->rrs.rdata);
		uint16_t bm_size = knot_nsec3_bitmap_len(rrset->rrs.rdata);
		if (kr_nsec_children_in_zone_check(bm, bm_size) != 0)
			continue; /* no fatal errors from bad RRs */
		/* Match the NSEC3 to sname or one of its ancestors. */
		unsigned skipped = 0;
		flags = 0;
		int ret = closest_encloser_match(&flags, rrset, sname, &skipped);
		if (ret != 0)
			return ret;
		if (!(flags & FLG_CLOSEST_PROVABLE_ENCLOSER))
			continue;
		matching = rrset;
		/* Construct the next closer name and try to cover it. */
		--skipped;
		next_closer = sname;
		for (unsigned j = 0; j < skipped; ++j) {
			if (kr_fails_assert(next_closer[0]))
				return kr_error(EINVAL);
			next_closer = knot_wire_next_label(next_closer, NULL);
		}
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *rrset_j = knot_pkt_rr(sec, j);
			if (rrset_j->type != KNOT_RRTYPE_NSEC3)
				continue;
			ret = covers_name(&flags, rrset_j, next_closer);
			if (ret != 0)
				return ret;
			if (flags & FLG_NAME_COVERED) {
				covering = rrset_j;
				break;
			}
		}
		if (flags & FLG_NAME_COVERED)
			break;
		flags = 0; //
	}

	if ((flags & FLG_CLOSEST_PROVABLE_ENCLOSER) && (flags & FLG_NAME_COVERED) && next_closer) {
		if (encloser_name && next_closer[0])
			*encloser_name = knot_wire_next_label(next_closer, NULL);
		if (matching_encloser_nsec3)
			*matching_encloser_nsec3 = matching;
		if (covering_next_nsec3)
			*covering_next_nsec3 = covering;
		return kr_ok();
	}

	return kr_error(ENOENT);
}

/**
 * Check whether any NSEC3 RR covers a wildcard RR at the closer encloser.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param encloser   Closest (provable) encloser domain name.
 * @return           0 or error code:
 *                   KNOT_ERANGE - NSEC3 RR (that covers a wildcard)
 *                   has been found, but has opt-out flag set;
 *                   otherwise - error.
 */
static int covers_closest_encloser_wildcard(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *encloser)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !encloser)
		return kr_error(EINVAL);

	uint8_t wildcard[KNOT_DNAME_MAXLEN];
	wildcard[0] = 1;
	wildcard[1] = '*';
	int encloser_len = knot_dname_size(encloser);
	if (encloser_len < 0)
		return encloser_len;
	memcpy(wildcard + 2, encloser, encloser_len);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3)
			continue;
		int ret = covers_name(&flags, rrset, wildcard);
		if (ret != 0)
			return ret;
		if (flags & FLG_NAME_COVERED) {
			return has_optout(rrset) ?
			       kr_error(KNOT_ERANGE) : kr_ok();
		}
	}

	return kr_error(ENOENT);
}

int kr_nsec3_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                       const knot_dname_t *sname)
{
	const knot_dname_t *encloser = NULL;
	const knot_rrset_t *covering_next_nsec3 = NULL;
	int ret = closest_encloser_proof(pkt, section_id, sname,
					 &encloser, NULL, &covering_next_nsec3);
	if (ret != 0)
		return ret;
	ret = covers_closest_encloser_wildcard(pkt, section_id, encloser);
	if (ret != 0) {
		/* OK, but NSEC3 for wildcard at encloser has opt-out;
		 * or error */
		return ret;
	}
	/* Closest encloser proof is OK and
	 * NSEC3 for wildcard has been found and optout flag is not set.
	 * Now check if NSEC3 that covers next closer name has opt-out. */
	return has_optout(covering_next_nsec3) ?
	       kr_error(KNOT_ERANGE) : kr_ok();
}

/**
 * Search the packet section for a matching NSEC3 with nodata-proving bitmap.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 * @note             This does NOT check the opt-out case if type is DS;
 *                   see RFC 5155 8.6.
 */
static int nodata_find(const knot_pkt_t *pkt, knot_section_t section_id,
			const knot_dname_t *name, const uint16_t type)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !name)
		return kr_error(EINVAL);

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *nsec3 = knot_pkt_rr(sec, i);
		/* Records causing any errors are simply skipped. */
		if (nsec3->type != KNOT_RRTYPE_NSEC3
		    || matches_name(nsec3, name) != kr_ok()) {
			continue;
			/* LATER(optim.): we repeatedly recompute the hash of `name` */
		}

		const uint8_t *bm = knot_nsec3_bitmap(nsec3->rrs.rdata);
		uint16_t bm_size = knot_nsec3_bitmap_len(nsec3->rrs.rdata);
		if (kr_nsec_bitmap_nodata_check(bm, bm_size, type, nsec3->owner) == kr_ok())
			return kr_ok();
	}

	return kr_error(ENOENT);
}

/**
 * Check whether NSEC3 RR matches a wildcard at the closest encloser and has given type bit missing.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param encloser   Closest (provable) encloser domain name.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
static int matches_closest_encloser_wildcard(const knot_pkt_t *pkt, knot_section_t section_id,
                                             const knot_dname_t *encloser, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !encloser)
		return kr_error(EINVAL);

	uint8_t wildcard[KNOT_DNAME_MAXLEN]; /**< the source of synthesis */
	int ret = prepend_asterisk(wildcard, sizeof(wildcard), encloser);
	if (ret < 0)
		return ret;
	kr_require(ret >= 3);
	return nodata_find(pkt, section_id, wildcard, stype);
}

int kr_nsec3_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *sname, int trim_to_next)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname)
		return kr_error(EINVAL);

	/* Compute the next closer name. */
	for (int i = 0; i < trim_to_next; ++i) {
		if (kr_fails_assert(sname[0]))
			return kr_error(EINVAL);
		sname = knot_wire_next_label(sname, NULL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3)
			continue;
		if (knot_nsec3_iters(rrset->rrs.rdata) > KR_NSEC3_MAX_ITERATIONS) {
			/* Avoid hashing with too many iterations.
			 * If we get here, the `sname` wildcard probably ends up bogus,
			 * but it gets downgraded to KR_RANK_INSECURE when validator
			 * gets to verifying one of these over-limit NSEC3 RRs. */
			continue;
		}
		int ret = covers_name(&flags, rrset, sname);
		if (ret != 0)
			return ret;
		if (flags & FLG_NAME_COVERED) {
			return has_optout(rrset) ?
			       kr_error(KNOT_ERANGE) : kr_ok();
		}
	}

	return kr_error(ENOENT);
}


int kr_nsec3_no_data(const knot_pkt_t *pkt, knot_section_t section_id,
                     const knot_dname_t *sname, uint16_t stype)
{
	/* DS record may be also matched by an existing NSEC3 RR. */
	int ret = nodata_find(pkt, section_id, sname, stype);
	if (ret == 0) {
		/* Satisfies RFC5155 8.5 and 8.6, both first paragraph. */
		return ret;
	}

	/* Find closest provable encloser. */
	const knot_dname_t *encloser_name = NULL;
	const knot_rrset_t *covering_next_nsec3 = NULL;
	ret = closest_encloser_proof(pkt, section_id, sname, &encloser_name,
                                     NULL, &covering_next_nsec3);
	if (ret != 0)
		return ret;

	if (kr_fails_assert(encloser_name && covering_next_nsec3))
		return kr_error(EFAULT);
	ret = matches_closest_encloser_wildcard(pkt, section_id,
	                                         encloser_name, stype);
	if (ret == 0) {
		/* Satisfies RFC5155 8.7 */
		if (has_optout(covering_next_nsec3)) {
			/* Opt-out is detected.
			 * Despite the fact that all records
			 * in the packet can be properly signed,
			 * AD bit must not be set due to rfc5155 9.2.
			 * Return appropriate code to the caller */
			ret = kr_error(KNOT_ERANGE);
		}
		return ret;
	}

	if (!has_optout(covering_next_nsec3)) {
		/* Bogus */
		ret = kr_error(ENOENT);
	} else {
		/*
		 * Satisfies RFC5155 8.6 (QTYPE == DS), 2nd paragraph.
		 * Also satisfies ERRATA 3441 8.5 (QTYPE != DS), 3rd paragraph.
		 * - (wildcard) empty nonterminal
		 * derived from unsecure delegation.
		 * Denial of existence can not be proven.
		 * Set error code to proceed unsecure.
		 */
		ret = kr_error(KNOT_ERANGE);
	}

	return ret;
}

int kr_nsec3_ref_to_unsigned(const knot_pkt_t *pkt)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_AUTHORITY);
	if (!sec)
		return kr_error(EINVAL);
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *ns = knot_pkt_rr(sec, i);
		if (ns->type == KNOT_RRTYPE_DS)
			return kr_error(EEXIST);
		if (ns->type != KNOT_RRTYPE_NS)
			continue;

		int flags = 0;
		bool nsec3_found = false;
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *nsec3 = knot_pkt_rr(sec, j);
			if (nsec3->type == KNOT_RRTYPE_DS)
				return kr_error(EEXIST);
			if (nsec3->type != KNOT_RRTYPE_NSEC3)
				continue;
			nsec3_found = true;
			/* nsec3 found, check if owner name matches the delegation name.
			 * Just skip in case of *any* errors. */
			if (matches_name(nsec3, ns->owner) != kr_ok())
				continue;

			const uint8_t *bm = knot_nsec3_bitmap(nsec3->rrs.rdata);
			uint16_t bm_size = knot_nsec3_bitmap_len(nsec3->rrs.rdata);
			if (!bm)
				return kr_error(EINVAL);
			if (dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_NS) &&
			    !dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_DS) &&
			    !dnssec_nsec_bitmap_contains(bm, bm_size,
							  KNOT_RRTYPE_SOA)) {
				/* Satisfies rfc5155, 8.9. paragraph 2 */
				return kr_ok();
			}
		}
		if (!nsec3_found)
			return kr_error(DNSSEC_NOT_FOUND);
		if (flags & FLG_NAME_MATCHED) {
			/* nsec3 which owner matches
			 * the delegation name was found,
			 * but nsec3 type bitmap contains wrong types
			 */
			return kr_error(EINVAL);
		}
		/* nsec3 that matches the delegation was not found.
		 * Check rfc5155, 8.9. paragraph 4.
		 * Find closest provable encloser.
		 */
		const knot_dname_t *encloser_name = NULL;
		const knot_rrset_t *covering_next_nsec3 = NULL;
		int ret = closest_encloser_proof(pkt, KNOT_AUTHORITY, ns->owner,
				&encloser_name, NULL, &covering_next_nsec3);
		if (ret != 0)
			return kr_error(EINVAL);

		if (has_optout(covering_next_nsec3)) {
			return kr_error(KNOT_ERANGE);
		} else {
			return kr_error(EINVAL);
		}
	}
	return kr_error(EINVAL);
}

int kr_nsec3_matches_name_and_type(const knot_rrset_t *nsec3,
				   const knot_dname_t *name, uint16_t type)
{
	/* It's not secure enough to just check a single bit for (some) other types,
	 * but we don't (currently) only use this API for NS.  See RFC 6840 sec. 4.
	 */
	if (kr_fails_assert(type == KNOT_RRTYPE_NS))
		return kr_error(EINVAL);
	int ret = matches_name(nsec3, name);
	if (ret)
		return kr_error(ret);
	const uint8_t *bm = knot_nsec3_bitmap(nsec3->rrs.rdata);
	uint16_t bm_size = knot_nsec3_bitmap_len(nsec3->rrs.rdata);
	if (!bm)
		return kr_error(EINVAL);
	if (dnssec_nsec_bitmap_contains(bm, bm_size, type)) {
		return kr_ok();
	} else {
		return kr_error(ENOENT);
	}
}
