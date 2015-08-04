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

#include <dnssec/error.h>
#include <dnssec/key.h>
#include <dnssec/sign.h>
#include <libknot/descriptor.h>
#include <libknot/packet/rrset-wire.h>
#include <libknot/packet/wire.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/defines.h"
#include "lib/dnssec/rrtype/ds.h"
#include "lib/dnssec/signature.h"

int kr_authenticate_referral(const knot_rrset_t *ref, const dnssec_key_t *key)
{
	assert(ref && key);
	if (ref->type != KNOT_RRTYPE_DS) {
		assert(0);
		return kr_error(EINVAL);
	}

	int ret = 0;
	dnssec_binary_t orig_ds_rdata;
	dnssec_binary_t generated_ds_rdata = {0, };

	{
		/* Obtain RDATA of the supplied DS. */
		const knot_rdata_t *rr = knot_rdataset_at(&ref->rrs, 0);
		orig_ds_rdata.size = knot_rdata_rdlen(rr);
		orig_ds_rdata.data = knot_rdata_data(rr);
	}

	/* Compute DS RDATA from the DNSKEY. */
	ret = dnssec_key_create_ds(key, _knot_ds_dtype(&ref->rrs, 0), &generated_ds_rdata);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	/* DS records contain algorithm, key tag and the digest.
	 * Therefore the comparison of the two DS is sufficient.
	 */
	ret = (orig_ds_rdata.size == generated_ds_rdata.size) &&
	    (memcmp(orig_ds_rdata.data, generated_ds_rdata.data, orig_ds_rdata.size) == 0);
	ret = ret ? kr_ok() : kr_error(KNOT_DNSSEC_ENOKEY);

fail:
	dnssec_binary_free(&generated_ds_rdata);
	return ret;
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
#undef RRSIG_RDATA_SIGNER_OFFSET

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
static int sign_ctx_add_records(dnssec_sign_ctx_t *ctx, const knot_rrset_t *covered,
                                int trim_labels)
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

	/* RFC4035 5.3.2
	 * Remove leftmost labels and replace them with '*.'.
	 */
	uint8_t *owner = rrwf;
	if (trim_labels > 0) {
		/**/
		for (int i = 0; i < trim_labels; ++i) {
			owner = (uint8_t *) knot_wire_next_label(owner, NULL);
		}
		*(--owner) = '*';
		*(--owner) = 1;
	}

	dnssec_binary_t rrset_wire = { 0 };
	rrset_wire.size = written - (owner - rrwf);
	rrset_wire.data = owner;
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
static int sign_ctx_add_data(dnssec_sign_ctx_t *ctx, const uint8_t *rrsig_rdata,
                             const knot_rrset_t *covered, int trim_labels)
{
	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered, trim_labels);
}

int kr_check_signature(const knot_rrset_t *rrsigs, size_t pos,
                       const dnssec_key_t *key, const knot_rrset_t *covered,
                       int trim_labels)
{
	if (!rrsigs || !key || !dnssec_key_can_verify(key)) {
		return kr_error(EINVAL);
	}

	int ret;
	dnssec_sign_ctx_t *sign_ctx = NULL;
	dnssec_binary_t signature = {0, };

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

	ret = sign_ctx_add_data(sign_ctx, rdata, covered, trim_labels);
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
