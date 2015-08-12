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
#include "lib/dnssec/nsec3.h"

#define OPT_OUT_BIT 0x01

//#define FLG_CLOSEST_ENCLOSER 0x01
#define FLG_CLOSEST_PROVABLE_ENCLOSER 0x02
#define FLG_NEXT_CLOSER_COVERED 0x04

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
 * Checks whether NSEC3 RR covers the supplied name.
 * @param flags Flags to be set according to check outcome.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @return      0 or error code.
 */
static int covers_next_closer(int *flags, const knot_rrset_t *nsec3,
                              const knot_dname_t *name)
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
	    (memcmp(owner_hash.data, name_hash.data, owner_hash.size) >= 0)) {
		goto fail;
	}

	uint8_t next_size = 0;
	uint8_t *next_hash = NULL;
	knot_nsec3_next_hashed(&nsec3->rrs, 0, &next_hash, &next_size);

	if ((name_hash.size != next_size) ||
	    (memcmp(name_hash.data, next_hash, name_hash.size) >= 0)) {
		goto fail;
	}

	*flags |= FLG_NEXT_CLOSER_COVERED;
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
 * Closest encloser proof (RFC5155 7.2.1).
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param encloser   Returned matching encloser, if found.
 * @return           0 or error code.
 */
static int closest_encloser_proof(const knot_pkt_t *pkt, knot_section_t section_id,
                                  const knot_dname_t *sname, const knot_dname_t **encloser)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname || !encloser) {
		return kr_error(EINVAL);
	}

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
			ret = covers_next_closer(&flags, rrset, next_closer);
			if (ret != 0) {
				return ret;
			}
			if (flags & FLG_NEXT_CLOSER_COVERED) {
				break;
			}
		}
		if (flags & FLG_NEXT_CLOSER_COVERED) {
			break;
		}
	}

	if ((flags & FLG_CLOSEST_PROVABLE_ENCLOSER) &&
	    (flags & FLG_NEXT_CLOSER_COVERED)) {
		*encloser = knot_wire_next_label(next_closer, NULL);
		return kr_ok();
	}

	return kr_error(EINVAL);
}

int kr_nsec3_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                      const knot_dname_t *sname, mm_ctx_t *pool)
{
	const knot_dname_t *encloser = NULL;
	int ret = closest_encloser_proof(pkt, section_id, sname, &encloser);
	fprintf(stderr, "%s() [%s %d]: Closest encloser proof: %d '%s'\n", __func__, __FILE__, __LINE__, ret, encloser);

	return kr_error(ENOSYS);
}
