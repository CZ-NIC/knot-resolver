/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <string.h>

#include <libdnssec/error.h>
#include <libdnssec/key.h>
#include <libdnssec/sign.h>
#include <libknot/descriptor.h>
#include <libknot/packet/rrset-wire.h>
#include <libknot/packet/wire.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>
#include <libknot/rrtype/ds.h>
#include <libknot/wire.h>

#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/dnssec/signature.h"

static int authenticate_ds(const dnssec_key_t *key, dnssec_binary_t *ds_rdata, uint8_t digest_type)
{
	/* Compute DS RDATA from the DNSKEY. */
	dnssec_binary_t computed_ds = { 0, };
	int ret = dnssec_key_create_ds(key, digest_type, &computed_ds);
	if (ret != DNSSEC_EOK)
		goto fail;

	/* DS records contain algorithm, key tag and the digest.
	 * Therefore the comparison of the two DS is sufficient.
	 */
	ret = (ds_rdata->size == computed_ds.size) &&
	    (memcmp(ds_rdata->data, computed_ds.data, ds_rdata->size) == 0);
	ret = ret ? kr_ok() : kr_error(ENOENT);

fail:
	dnssec_binary_free(&computed_ds);
	return kr_error(ret);
}

int kr_authenticate_referral(const knot_rrset_t *ref, const dnssec_key_t *key)
{
	if (!kr_assume(ref && key))
		return kr_error(EINVAL);
	if (ref->type != KNOT_RRTYPE_DS)
		return kr_error(EINVAL);

	/* Try all possible DS records */
	int ret = 0;
	knot_rdata_t *rd = ref->rrs.rdata;
	for (uint16_t i = 0; i < ref->rrs.count; ++i) {
		dnssec_binary_t ds_rdata = {
			.size = rd->len,
			.data = rd->data
		};
		ret = authenticate_ds(key, &ds_rdata, knot_ds_digest_type(rd));
		if (ret == 0) /* Found a good DS */
			return kr_ok();
		rd = knot_rdataset_next(rd);
	}

	return kr_error(ret);
}

/**
 * Adjust TTL in wire format.
 * @param wire      RR Set in wire format.
 * @param wire_size Size of the wire data portion.
 * @param new_ttl   TTL value to be set for all RRs.
 * @return          0 or error code.
 */
static int adjust_wire_ttl(uint8_t *wire, size_t wire_size, uint32_t new_ttl)
{
	if (!kr_assume(wire))
		return kr_error(EINVAL);
	static_assert(sizeof(uint16_t) == 2, "uint16_t must be exactly 2 bytes");
	static_assert(sizeof(uint32_t) == 4, "uint32_t) must be exactly 4 bytes");
	uint16_t rdlen;

	int ret;

	new_ttl = htonl(new_ttl);

	size_t i = 0;
	/* RR wire format in RFC1035 3.2.1 */
	while(i < wire_size) {
		ret = knot_dname_size(wire + i);
		if (ret < 0)
			return ret;
		i += ret + 4;
		memcpy(wire + i, &new_ttl, sizeof(uint32_t));
		i += sizeof(uint32_t);

		memcpy(&rdlen, wire + i, sizeof(uint16_t));
		rdlen = ntohs(rdlen);
		i += sizeof(uint16_t) + rdlen;

		if (!kr_assume(i <= wire_size))
			return kr_error(EINVAL);
	}

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
	if (!kr_assume(ctx && rdata))
		return kr_error(EINVAL);

	int result;

	// static header

	dnssec_binary_t header = {
		.data = (uint8_t *)rdata,
		.size = RRSIG_RDATA_SIGNER_OFFSET,
	};

	result = dnssec_sign_add(ctx, &header);
	if (result != DNSSEC_EOK)
		return result;

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
                                uint32_t orig_ttl, int trim_labels)
{
	if (!ctx || !covered || trim_labels < 0)
		return kr_error(EINVAL);

	// huge block of rrsets can be optionally created
	static uint8_t wire_buffer[KNOT_WIRE_MAX_PKTSIZE];
	int written = knot_rrset_to_wire(covered, wire_buffer, sizeof(wire_buffer), NULL);
	if (written < 0)
		return written;

	/* Set original ttl. */
	int ret = adjust_wire_ttl(wire_buffer, written, orig_ttl);
	if (ret != 0)
		return ret;

	if (!trim_labels) {
		const dnssec_binary_t wire_binary = {
			.size = written,
			.data = wire_buffer
		};
		return dnssec_sign_add(ctx, &wire_binary);
	}

	/* RFC4035 5.3.2
	 * Remove leftmost labels and replace them with '*.'
	 * for each RR in covered.
	 */
	uint8_t *beginp = wire_buffer;
	for (uint16_t i = 0; i < covered->rrs.count; ++i) {
		/* RR(i) = name | type | class | OrigTTL | RDATA length | RDATA */
		for (int j = 0; j < trim_labels; ++j) {
			if (!kr_assume(beginp[0]))
				return kr_error(EINVAL);
			beginp = (uint8_t *) knot_wire_next_label(beginp, NULL);
			if (!kr_assume(beginp))
				return kr_error(EFAULT);
		}
		*(--beginp) = '*';
		*(--beginp) = 1;
		const size_t rdatalen_offset = knot_dname_size(beginp) + /* name */
			sizeof(uint16_t) + /* type */
			sizeof(uint16_t) + /* class */
			sizeof(uint32_t);  /* OrigTTL */
		const uint8_t *rdatalen_ptr = beginp + rdatalen_offset;
		const uint16_t rdata_size = knot_wire_read_u16(rdatalen_ptr);
		const size_t rr_size = rdatalen_offset +
			sizeof(uint16_t) + /* RDATA length */
			rdata_size;        /* RDATA */
		const dnssec_binary_t wire_binary = {
			.size = rr_size,
			.data = beginp
		};
		ret = dnssec_sign_add(ctx, &wire_binary);
		if (ret != 0)
			break;
		beginp += rr_size;
	}
	return ret;
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
                             const knot_rrset_t *covered, uint32_t orig_ttl, int trim_labels)
{
	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK)
		return result;

	return sign_ctx_add_records(ctx, covered, orig_ttl, trim_labels);
}

int kr_check_signature(const knot_rdata_t *rrsig,
                       const dnssec_key_t *key, const knot_rrset_t *covered,
                       int trim_labels)
{
	if (!rrsig || !key || !dnssec_key_can_verify(key))
		return kr_error(EINVAL);

	int ret = 0;
	dnssec_sign_ctx_t *sign_ctx = NULL;
	dnssec_binary_t signature = {
		.data = /*const-cast*/(uint8_t*)knot_rrsig_signature(rrsig),
		.size = knot_rrsig_signature_len(rrsig),
	};
	if (!signature.data || !signature.size) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	if (dnssec_sign_new(&sign_ctx, key) != 0) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	uint32_t orig_ttl = knot_rrsig_original_ttl(rrsig);

	if (sign_ctx_add_data(sign_ctx, rrsig->data, covered, orig_ttl, trim_labels) != 0) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = dnssec_sign_verify(sign_ctx,
		#if KNOT_VERSION_MAJOR >= 3
			false,
		#endif
			&signature);
	if (ret != 0) {
		ret = kr_error(EBADMSG);
		goto fail;
	}

	ret = kr_ok();

fail:
	dnssec_sign_free(sign_ctx);
	return ret;
}
