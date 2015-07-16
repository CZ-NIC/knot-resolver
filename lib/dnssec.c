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
#include <dnssec/binary.h>
#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/key.h>
#include <dnssec/sign.h>
#include <libknot/descriptor.h>
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/dnskey.h>
#include <libknot/rrtype/rrsig.h>


#include "lib/defines.h"
#include "lib/dnssec.h"

#define DEBUG_MSG(fmt...) fprintf(stderr, fmt)

void kr_crypto_init(void)
{
	dnssec_crypto_init();
}

void kr_crypto_cleanup(void)
{
	dnssec_crypto_cleanup();
}

void kr_crypto_reinit(void)
{
	dnssec_crypto_reinit();
}

static inline
uint16_t _knot_ds_ktag(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return wire_read_u16(knot_rdata_offset(rrs, pos, 0));
}

static inline
uint8_t _knot_ds_alg(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 2);
}

static inline
uint8_t _knot_ds_dtype(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 3);
}

static inline
void _knot_ds_digest(const knot_rdataset_t *rrs, size_t pos,
                    uint8_t **digest, uint16_t *digest_size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);
	*digest = knot_rdata_offset(rrs, pos, 4);
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	*digest_size = knot_rdata_rdlen(rr) - 4;
}

/* RFC4035 5.2, bullet 2 */
static int authenticate_referral(const dnssec_key_t *key, const knot_rrset_t *ds)
{
	assert(key && ds);
	assert(ds->type == KNOT_RRTYPE_DS);

	int ret = 0;
	dnssec_binary_t orig_ds_rdata;
	dnssec_binary_t generated_ds_rdata = {0, };

	{
		/* Obtain RDATA of the supplied DS. */
		const knot_rdata_t *rr = knot_rdataset_at(&ds->rrs, 0);
		orig_ds_rdata.size = knot_rdata_rdlen(rr);
		orig_ds_rdata.data = knot_rdata_data(rr);
	}

	/* Compute DS RDATA from the DNSKEY. */
	ret = dnssec_key_create_ds(key, _knot_ds_dtype(&ds->rrs, 0), &generated_ds_rdata);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	/* DS records contain algorithm, key tag and the digest.
	 * Therefore the comparison of the two DS is sufficient.
	 */
	ret = ((orig_ds_rdata.size == generated_ds_rdata.size) &&
	    (memcmp(orig_ds_rdata.data, generated_ds_rdata.data, orig_ds_rdata.size) == 0)) ? kr_ok() : kr_error(KNOT_DNSSEC_ENOKEY);

fail:
	dnssec_binary_free(&generated_ds_rdata);
	return ret;
}

/* RFC4035 5.3.1 */
static int validate_rrsig_rr(const knot_rrset_t *rrset, const knot_rrset_t *rrsig,
                             const knot_rrset_t *keys, size_t pos, const dnssec_key_t *key,
                             const knot_dname_t *zone_name, uint32_t timestamp)
{
	if (!rrset || !rrsig || !keys || !key || !zone_name) {
		return kr_error(EINVAL);
	}
#warning TODO: Make the comparison case-insensitive.
	/* bullet 1 */
	if ((rrset->rclass != rrsig->rclass) || (knot_dname_cmp(rrset->owner, rrsig->owner) != 0)) {
		return kr_error(EINVAL);
	}
	/* bullet 2 */
	const knot_dname_t *signer_name = knot_rrsig_signer_name(&rrsig->rrs, 0);
	if (signer_name == NULL) {
		return kr_error(EINVAL);
	}
	if (knot_dname_cmp(signer_name, zone_name) != 0) {
		return kr_error(EINVAL);
	}
	/* bullet 3 */
	uint16_t tcovered = knot_rrsig_type_covered(&rrsig->rrs, 0);
	if (tcovered != rrset->type) {
		return kr_error(EINVAL);
	}
	/* bullet 4 */
	if (knot_rrsig_labels(&rrsig->rrs, 0) > knot_dname_labels(rrset->owner, NULL)) {
		return kr_error(EINVAL);
	}
	/* bullet 5 */
	if (knot_rrsig_sig_expiration(&rrsig->rrs, 0) < timestamp) {
		return kr_error(EINVAL);
	}
	/* bullet 6 */
	if (knot_rrsig_sig_inception(&rrsig->rrs, 0) > timestamp) {
		return kr_error(EINVAL);
	}
	/* bullet 7 */
	if ((knot_dname_cmp(keys->owner, signer_name) != 0) ||
	    (knot_dnskey_alg(&keys->rrs, pos) != knot_rrsig_algorithm(&rrsig->rrs, 0)) ||
	    (dnssec_key_get_keytag(key) != knot_rrsig_key_tag(&rrsig->rrs, 0))) {
		return kr_error(EINVAL);
	}
	/* bullet 8 */
	/* Checked somewhere else. */
	/* bullet 9 and 10 */
	/* One of the requirements should be always fulfilled. */

	return kr_ok();
}

/*!
 * \brief Add RRSIG RDATA without signature to signing context.
 *
 * Requires signer name in RDATA in canonical form.
 *
 * \param ctx   Signing context.
 * \param rdata Pointer to RRSIG RDATA.
 *
 * \return Error code, KNOT_EOK if successful.
 */
#define RRSIG_RDATA_SIGNER_OFFSET 18
static int sign_ctx_add_self(dnssec_sign_ctx_t *ctx, const uint8_t *rdata)
{
	assert(ctx);
	assert(rdata);

	int result;

	// static header

	dnssec_binary_t header = { 0 };
	header.data = (uint8_t *)rdata;
	header.size = RRSIG_RDATA_SIGNER_OFFSET;

	result = dnssec_sign_add(ctx, &header);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// signer name

	const uint8_t *rdata_signer = rdata + RRSIG_RDATA_SIGNER_OFFSET;
	dnssec_binary_t signer = { 0 };
	signer.data = knot_dname_copy(rdata_signer, NULL);
	signer.size = knot_dname_size(signer.data);

	result = dnssec_sign_add(ctx, &signer);
	free(signer.data);

	return result;
}

/*!
 * \brief Add covered RRs to signing context.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx      Signing context.
 * \param covered  Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_records(dnssec_sign_ctx_t *ctx, const knot_rrset_t *covered)
{
	// huge block of rrsets can be optionally created
	uint8_t *rrwf = malloc(KNOT_WIRE_MAX_PKTSIZE);
	if (!rrwf) {
		return KNOT_ENOMEM;
	}

	int written = knot_rrset_to_wire(covered, rrwf, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (written < 0) {
		free(rrwf);
		return written;
	}

	dnssec_binary_t rrset_wire = { 0 };
	rrset_wire.size = written;
	rrset_wire.data = rrwf;
	int result = dnssec_sign_add(ctx, &rrset_wire);
	free(rrwf);

	return result;
}

/*!
 * \brief Add all data covered by signature into signing context.
 *
 * RFC 4034: The signature covers RRSIG RDATA field (excluding the signature)
 * and all matching RR records, which are ordered canonically.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx          Signing context.
 * \param rrsig_rdata  RRSIG RDATA with populated fields except signature.
 * \param covered      Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
/* TODO -- Taken from knot/src/knot/dnssec/rrset-sign.c. Re-write for better fit needed. */
static int sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                             const uint8_t *rrsig_rdata,
                             const knot_rrset_t *covered)
{
	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered);
}

/* RFC4035 5.3.3 and 5.3.2 */
static int check_signature(const knot_rrset_t *rrsigs, size_t pos,
                           const dnssec_key_t *key, const dnssec_key_t *covered)
{
	if (!rrsigs || !key || !dnssec_key_can_verify(key)) {
		return kr_error(EINVAL);
	}

	int ret;
	dnssec_sign_ctx_t *sign_ctx = NULL;
	dnssec_binary_t signature = {0, };
	dnssec_binary_t new_signed = {0, };

	knot_rrsig_signature(&rrsigs->rrs, pos, &signature.data, &signature.size);
	if (!signature.data || !signature.size) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	ret = dnssec_sign_new(&sign_ctx, key);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	const knot_rdata_t *rr_data = knot_rdataset_at(&rrsigs->rrs, pos);
	uint8_t *rdata = knot_rdata_data(rr_data);

	ret = sign_ctx_add_data(sign_ctx, rdata, covered);
	if (ret != KNOT_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = dnssec_sign_verify(sign_ctx, &signature);
	if (ret != KNOT_EOK) {
#warning TODO: proper DNSSEC error codes needed
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = kr_ok();

fail:
	dnssec_sign_free(sign_ctx);
	return ret;
}

/** Validate RRSet in canonical format. */
static int crrset_validate(const knot_pktsection_t *sec, const knot_rrset_t *rrset,
                           const knot_rrset_t *keys, size_t pos, const dnssec_key_t *key,
                           const knot_dname_t *zone_name, uint32_t timestamp)
{
	int ret = kr_error(KNOT_DNSSEC_ENOKEY);
	for (unsigned i = 0; i < sec->count; ++i) {
		/* Try every RRSIG. */
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type != KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if (validate_rrsig_rr(rrset, rr, keys, pos, key, zone_name, timestamp) != 0) {
			continue;
		}
		if (check_signature(rr, 0, key, keys) != 0) {
			continue;
		}
		ret = kr_ok();
		break;
	}

	return ret;
}

int kr_dnskeys_trusted(const knot_pktsection_t *sec, const knot_rrset_t *keys,
                       const knot_rrset_t *ta, const knot_dname_t *zone_name, uint32_t timestamp)
{
	if (!sec || !keys || !ta) {
		return kr_error(EINVAL);
	}

	/* RFC4035 5.2, bullet 1
	 * The supplied DS record has been authenticated.
	 * It has been validated or is part of a configured trust anchor.
	 *
	 * This implementation actually ignores the SEP flag.
	 */

#warning TODO: there should be an error saying that there is no matching key
	int ret = kr_error(KNOT_DNSSEC_ENOKEY);
	for (uint16_t i = 0; i < keys->rrs.rr_count; ++i) {
		/* RFC4035 5.3.1, bullet 8 */ /* ZSK */
		if (!(knot_dnskey_flags(&keys->rrs, i) & 0x0100)) {
			continue;
		}
		const knot_rdata_t *krr = knot_rdataset_at(&keys->rrs, i);
		struct dseckey *key;
		if (kr_dnssec_key_from_rdata(&key, krr, keys->owner) != 0) {
			continue;
		}
		if (authenticate_referral((dnssec_key_t *) key, ta) != 0) {
			kr_dnssec_key_free(&key);
			continue;
		}
		if (crrset_validate(sec, keys, keys, i, (dnssec_key_t *) key, zone_name, timestamp) != 0) {
			kr_dnssec_key_free(&key);
			continue;
		}
		kr_dnssec_key_free(&key);
		ret = kr_ok();
		break;
	}

	if (ret != 0) {
		return ret;
	}

	return kr_error(ENOSYS);
}

int kr_dnssec_key_from_rdata(struct dseckey **key, const knot_rdata_t *krdata, const knot_dname_t *kown)
{
	assert(key);

	dnssec_key_t *new_key = NULL;
	dnssec_binary_t binary_key;
	int ret;

	ret = dnssec_key_new(&new_key);
	if (ret != DNSSEC_EOK) {
		return kr_error(ENOMEM);
	}

	binary_key.size = knot_rdata_rdlen(krdata);
	binary_key.data = knot_rdata_data(krdata);
	if (!binary_key.size || !binary_key.data) {
		dnssec_key_free(new_key);
		return kr_error(KNOT_DNSSEC_ENOKEY);
	}
	ret = dnssec_key_set_rdata(new_key, &binary_key);
	if (ret != DNSSEC_EOK) {
		dnssec_key_free(new_key);
		return kr_error(ENOMEM);
	}

	ret = dnssec_key_set_dname(new_key, kown);
	if (ret != DNSSEC_EOK) {
		dnssec_key_free(new_key);
		return kr_error(ENOMEM);
	}

	*key = (struct dseckey *) new_key;
	return kr_ok();
}

void kr_dnssec_key_free(struct dseckey **key)
{
	assert(key);

	dnssec_key_free((dnssec_key_t *) *key);
	*key = NULL;
}
