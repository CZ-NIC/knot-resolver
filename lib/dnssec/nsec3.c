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
#include <string.h>

#include <dnssec/binary.h>
#include <dnssec/error.h>
#include <dnssec/nsec.h>
#include <libknot/descriptor.h>
#include <libknot/internal/base32hex.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/nsec3.h>

#include "lib/defines.h"
#include "lib/dnssec/nsec.h"
#include "lib/dnssec/nsec3.h"

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
#define SALT_OFFSET 5
	assert(params && nsec3);

	const knot_rdata_t *rr = knot_rdataset_at(&nsec3->rrs, 0);
	assert(rr);

	/* Every NSEC3 RR contains data from NSEC3PARAMS. */
	dnssec_binary_t rdata = {0, };
	rdata.size = SALT_OFFSET + (size_t) knot_nsec3_salt_length(&nsec3->rrs, 0);
	rdata.data = knot_rdata_data(rr);

	int ret = dnssec_nsec3_params_from_rdata(params, &rdata);
	if (ret != DNSSEC_EOK) {
		return kr_error(EINVAL);
	}

	return kr_ok();
#undef SALT_OFFSET
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
	assert(hash && params && name);

	dnssec_binary_t dname = {0, };
	dname.size = knot_dname_size(name);
	dname.data = (uint8_t *) name;

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
	assert(hash && nsec3);
	assert(hash->data);

	int32_t ret = base32hex_decode(nsec3->owner + 1, nsec3->owner[0], hash->data, max_hash_size);
	if (ret < 0) {
		return ret;
	}
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
	assert(flags && nsec3 && name && skipped);

	dnssec_binary_t owner_hash = {0, };
	uint8_t hash_data[MAX_HASH_BYTES] = {0, };
	owner_hash.data = hash_data;
	dnssec_nsec3_params_t params = {0, };
	dnssec_binary_t name_hash = {0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0) {
		goto fail;
	}

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0) {
		goto fail;
	}

	const knot_dname_t *encloser = knot_wire_next_label(name, NULL);
	*skipped = 1;

	do {
		ret = hash_name(&name_hash, &params, encloser);
		if (ret != 0) {
			goto fail;
		}

		if ((owner_hash.size == name_hash.size) &&
		    (memcmp(owner_hash.data, name_hash.data, owner_hash.size) == 0)) {
			dnssec_binary_free(&name_hash);
			*flags |= FLG_CLOSEST_PROVABLE_ENCLOSER;
			break;
		}

		dnssec_binary_free(&name_hash);

		encloser = knot_wire_next_label(encloser, NULL);
		++(*skipped);
	} while (encloser && (encloser[0] != '\0'));

	ret = kr_ok();

fail:
	if (params.salt.data) {
		dnssec_nsec3_params_free(&params);
	}
	if (name_hash.data) {
		dnssec_binary_free(&name_hash);
	}
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
	assert(flags && nsec3 && name);

	dnssec_binary_t owner_hash = {0, };
	uint8_t hash_data[MAX_HASH_BYTES] = {0, };
	owner_hash.data = hash_data;
	dnssec_nsec3_params_t params = {0, };
	dnssec_binary_t name_hash = {0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0) {
		goto fail;
	}

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0) {
		goto fail;
	}

	ret = hash_name(&name_hash, &params, name);
	if (ret != 0) {
		goto fail;
	}

	uint8_t next_size = 0;
	uint8_t *next_hash = NULL;
	knot_nsec3_next_hashed(&nsec3->rrs, 0, &next_hash, &next_size);

	if ((owner_hash.size != next_size) || (name_hash.size != next_size)) {
		/* All hash lengths must be same. */
		goto fail;
	}

	const uint8_t *ownrd = owner_hash.data;
	const uint8_t *nextd = next_hash;
	if (memcmp(ownrd, nextd, next_size) < 0) {
		/*
		 * 0 (...) owner ... next (...) MAX
		 *                ^
		 *                name
		 * ==>
		 * (owner < name) && (name < next)
		 */
		if ((memcmp(ownrd, name_hash.data, next_size) >= 0) ||
		    (memcmp(name_hash.data, nextd, next_size) >= 0)) {
			goto fail;
		}
	} else {
		/*
		 * owner ... MAX, 0 ... next
		 *        ^     ^    ^
		 *        name  name name
		 * =>
		 * (owner < name) || (name < next)
		 */
		if ((memcmp(ownrd, name_hash.data, next_size) >= 0) &&
		    (memcmp(name_hash.data, nextd, next_size) >= 0)) {
			goto fail;
		}
	}

	*flags |= FLG_NAME_COVERED;

	uint8_t nsec3_flags = knot_nsec3_flags(&nsec3->rrs, 0);
	if (nsec3_flags & ~OPT_OUT_BIT) {
		/* RFC5155 3.1.2 */
		ret = kr_error(EINVAL);
	}

	ret = kr_ok();

fail:
	if (params.salt.data) {
		dnssec_nsec3_params_free(&params);
	}
	if (name_hash.data) {
		dnssec_binary_free(&name_hash);
	}
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
	if (!nsec3) {
		return false;
	}

	uint8_t nsec3_flags = knot_nsec3_flags(&nsec3->rrs, 0);
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
 * @return      0 or error code.
 */
static int matches_name(int *flags, const knot_rrset_t *nsec3, const knot_dname_t *name)
{
	assert(flags && nsec3 && name);

	dnssec_binary_t owner_hash = {0, };
	uint8_t hash_data[MAX_HASH_BYTES] = {0, };
	owner_hash.data = hash_data;
	dnssec_nsec3_params_t params = {0, };
	dnssec_binary_t name_hash = {0, };

	int ret = read_owner_hash(&owner_hash, MAX_HASH_BYTES, nsec3);
	if (ret != 0) {
		goto fail;
	}

	ret = nsec3_parameters(&params, nsec3);
	if (ret != 0) {
		goto fail;
	}

	ret = hash_name(&name_hash, &params, name);
	if (ret != 0) {
		goto fail;
	}

	if ((owner_hash.size != name_hash.size) ||
	    (memcmp(owner_hash.data, name_hash.data, owner_hash.size) != 0)) {
		goto fail;
	}

	*flags |= FLG_NAME_MATCHED;
	ret = kr_ok();

fail:
	if (params.salt.data) {
		dnssec_nsec3_params_free(&params);
	}
	if (name_hash.data) {
		dnssec_binary_free(&name_hash);
	}
	return ret;
}
#undef MAX_HASH_BYTES

/**
 * Prepends an asterisk label to given name.
 *
 * @param tgt  Target buffer to write domain name into.
 * @param name Name to be added to the asterisk.
 * @return     0 or error code
 */
int prepend_asterisk(uint8_t tgt[KNOT_DNAME_MAXLEN], const knot_dname_t *name)
{
	tgt[0] = 1;
	tgt[1] = '*';
	tgt[2] = 0;
	int name_len = knot_dname_size(name);
	if (name_len < 0) {
		return name_len;
	}
	memcpy(tgt + 2, name, name_len);
	return 0;
}

/**
 * Closest encloser proof (RFC5155 7.2.1).
 * @note No RRSIGs are validated.
 * @param pkt                    Packet structure to be processed.
 * @param section_id             Packet section to be processed.
 * @param sname                  Name to be checked.
 * @param encloser_name          Returned matching encloser name, if found.
 * @param matching_ecloser_nsec3 Pointer to matching encloser NSEC RRSet.
 * @param covering_next_nsec3    Pointer to covering next closer NSEC3 RRSet.
 * @return                       0 or error code.
 */
static int closest_encloser_proof(const knot_pkt_t *pkt, knot_section_t section_id,
                                  const knot_dname_t *sname, const knot_dname_t **encloser_name,
                                  const knot_rrset_t **matching_ecloser_nsec3, const knot_rrset_t **covering_next_nsec3)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	const knot_rrset_t *matching = NULL;
	const knot_rrset_t *covering = NULL;

	int ret = kr_error(ENOENT);
	int flags;
	const knot_dname_t *next_closer = NULL;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3) {
			continue;
		}
		unsigned skipped = 0;
		flags = 0;
		ret = closest_encloser_match(&flags, rrset, sname, &skipped);
		if (ret != 0) {
			return ret;
		}
		if (!(flags & FLG_CLOSEST_PROVABLE_ENCLOSER)) {
			continue;
		}
		matching = rrset;
		--skipped;
		next_closer = sname;
		for (unsigned j = 0; j < skipped; ++j) {
			next_closer = knot_wire_next_label(next_closer, NULL);
		}
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *rrset = knot_pkt_rr(sec, j);
			if (rrset->type != KNOT_RRTYPE_NSEC3) {
				continue;
			}
			ret = covers_name(&flags, rrset, next_closer);
			if (ret != 0) {
				return ret;
			}
			if (flags & FLG_NAME_COVERED) {
				covering = rrset;
				break;
			}
		}
		if (flags & FLG_NAME_COVERED) {
			break;
		}
		flags = 0; //
	}

	if ((flags & FLG_CLOSEST_PROVABLE_ENCLOSER) &&
	    (flags & FLG_NAME_COVERED)) {
		if (encloser_name) {
			*encloser_name = knot_wire_next_label(next_closer, NULL);
		}
		if (matching_ecloser_nsec3) {
			*matching_ecloser_nsec3 = matching;
		}
		if (covering_next_nsec3) {
			*covering_next_nsec3 = covering;
		}
		return kr_ok();
	}

	return kr_error(ENOENT);
}

/**
 * Check whether any NSEC3 RR covers a wildcard RR at the closer encloser.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param encloser   Closest (provable) encloser domain name.
 * @return           0 or error code.
 */
static int covers_closest_encloser_wildcard(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *encloser)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !encloser) {
		return kr_error(EINVAL);
	}

	uint8_t wildcard[KNOT_DNAME_MAXLEN];
	wildcard[0] = 1;
	wildcard[1] = '*';
	int encloser_len = knot_dname_size(encloser);
	if (encloser_len < 0) {
		return encloser_len;
	}
	memcpy(wildcard + 2, encloser, encloser_len);

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3) {
			continue;
		}
		int ret = covers_name(&flags, rrset, wildcard);
		if (ret != 0) {
			return ret;
		}
		if (flags & FLG_NAME_COVERED) {
			return kr_ok();
		}
	}

	return kr_error(ENOENT);
}

int kr_nsec3_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                       const knot_dname_t *sname)
{
	const knot_dname_t *encloser = NULL;
	int ret = closest_encloser_proof(pkt, section_id, sname, &encloser, NULL, NULL);
	if (ret != 0) {
		return ret;
	}
	return covers_closest_encloser_wildcard(pkt, section_id, encloser);
}

/**
 * Checks whether supplied NSEC3 RR matches the supplied name and type.
 * @param flags Flags to be set according to check outcome.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @param type  Type to be checked.
 * @return      0 or error code.
 */
static int maches_name_and_type(int *flags, const knot_rrset_t *nsec3,
                                const knot_dname_t *name, uint16_t type)
{
	assert(flags && nsec3 && name);

	int ret = matches_name(flags, nsec3, name);
	if (ret != 0) {
		return ret;
	}

	if (!(*flags & FLG_NAME_MATCHED)) {
		return kr_ok();
	}

	uint8_t *bm = NULL;
	uint16_t bm_size;
	knot_nsec3_bitmap(&nsec3->rrs, 0, &bm, &bm_size);
	if (!bm) {
		return kr_error(EINVAL);
	}

	if (!kr_nsec_bitmap_contains_type(bm, bm_size, type)) {
		*flags |= FLG_TYPE_BIT_MISSING;
		if (type == KNOT_RRTYPE_CNAME) {
			*flags |= FLG_CNAME_BIT_MISSING;
		}
	}

	if ((type != KNOT_RRTYPE_CNAME) &&
	    !kr_nsec_bitmap_contains_type(bm, bm_size, KNOT_RRTYPE_CNAME)) {
		*flags |= FLG_CNAME_BIT_MISSING;
	}

	return kr_ok();
}

/**
 * No data response check, no DS (RFC5155 7.2.3).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
static int no_data_response_no_ds(const knot_pkt_t *pkt, knot_section_t section_id,
                                  const knot_dname_t *sname, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	int flags;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3) {
			continue;
		}
		flags = 0;

		int ret = maches_name_and_type(&flags, rrset, sname, stype);
		if (ret != 0) {
			return ret;
		}

		if ((flags & FLG_NAME_MATCHED) &&
		    (flags & FLG_TYPE_BIT_MISSING) &&
		    (flags & FLG_CNAME_BIT_MISSING)) {
			return kr_ok();
		}
	}

	return kr_error(ENOENT);
}

/**
 * No data response check, DS (RFC5155 7.2.4, 2nd paragraph).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
static int no_data_response_ds(const knot_pkt_t *pkt, knot_section_t section_id,
                               const knot_dname_t *sname, uint16_t stype)
{
	assert(pkt && sname);
	if (stype != KNOT_RRTYPE_DS) {
		return kr_error(EINVAL);
	}

	const knot_rrset_t *covering_nsec3 = NULL;
	int ret = closest_encloser_proof(pkt, section_id, sname, NULL, NULL, &covering_nsec3);
	if (ret != 0) {
		return ret;
	}

	if (has_optout(covering_nsec3)) {
		return kr_ok();
	}

	return kr_error(ENOENT);
}

int kr_nsec3_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                    const knot_dname_t *sname, uint16_t stype)
{
	/* DS record may be matched by an existing NSEC3 RR. */
	int ret = no_data_response_no_ds(pkt, section_id, sname, stype);
	if ((ret == 0) || (stype != KNOT_RRTYPE_DS)) {
		return ret;
	}
	/* Closest provable encloser proof must be performed else. */
	return no_data_response_ds(pkt, section_id, sname, stype);
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
	if (!sec || !encloser) {
		return kr_error(EINVAL);
	}

	uint8_t wildcard[KNOT_DNAME_MAXLEN];
	int ret = prepend_asterisk(wildcard, encloser);
	if (ret != 0) {
		return ret;
	}

	int flags;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3) {
			continue;
		}
		flags = 0;

		int ret = maches_name_and_type(&flags, rrset, wildcard, stype);
		if (ret != 0) {
			return ret;
		}

		/* TODO -- The loop resembles no_data_response_no_ds() exept
		 * the following condition.
		 */
		if ((flags & FLG_NAME_MATCHED) && (flags & FLG_TYPE_BIT_MISSING)) {
			return kr_ok();
		}
	}

	return kr_error(ENOENT);
}

int kr_nsec3_wildcard_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                             const knot_dname_t *sname, uint16_t stype)
{
	const knot_dname_t *encloser = NULL;
	int ret = closest_encloser_proof(pkt, section_id, sname, &encloser, NULL, NULL);
	if (ret != 0) {
		return ret;
	}
	return matches_closest_encloser_wildcard(pkt, section_id, encloser, stype);
}

int kr_nsec3_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *sname, int trim_to_next)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	/* Compute the next closer name. */
	for (int i = 0; i < trim_to_next; ++i) {
		sname = knot_wire_next_label(sname, NULL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC3) {
			continue;
		}
		int ret = covers_name(&flags, rrset, sname);
		if (ret != 0) {
			return ret;
		}
		if (flags & FLG_NAME_COVERED) {
			return kr_ok();
		}
	}

	return kr_error(ENOENT);
}

int kr_nsec3_no_data(const knot_pkt_t *pkt, knot_section_t section_id,
                     const knot_dname_t *sname, uint16_t stype)
{
	/* DS record may be also matched by an existing NSEC3 RR. */
	int ret = no_data_response_no_ds(pkt, section_id, sname, stype);
	if (ret == 0) {
		/* Satisfies RFC5155 8.5 and 8.6, first paragraph. */
		return ret;
	}

	/* Find closest provable encloser. */
	const knot_dname_t *encloser_name = NULL;
	const knot_rrset_t *covering_next_nsec3 = NULL;
	ret = closest_encloser_proof(pkt, section_id, sname, &encloser_name,
                                     NULL, &covering_next_nsec3);
	if (ret != 0) {
		return ret;
	}

	assert(encloser_name && covering_next_nsec3);
	if ((stype == KNOT_RRTYPE_DS) && has_optout(covering_next_nsec3)) {
		/* Satisfies RFC5155 8.6, second paragraph. */
		return 0;
	}

	return matches_closest_encloser_wildcard(pkt, section_id,
	                                         encloser_name, stype);
}
