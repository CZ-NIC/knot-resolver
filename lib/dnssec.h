/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/defines.h"
#include "lib/utils.h"
#include <libknot/packet/pkt.h>

/**
 * Initialise cryptographic back-end.
 */
KR_EXPORT
void kr_crypto_init(void);

/**
 * De-initialise cryptographic back-end.
 */
KR_EXPORT
void kr_crypto_cleanup(void);

/**
 * Re-initialise cryptographic back-end.
 * @note Must be called after fork() in the child.
 */
KR_EXPORT
void kr_crypto_reinit(void);

#define KR_DNSSEC_VFLG_WEXPAND 0x01
#define KR_DNSSEC_VFLG_OPTOUT  0x02

/** DNSSEC validation context. */
struct kr_rrset_validation_ctx {
	const knot_pkt_t *pkt;		/*!< Packet to be validated. */
	ranked_rr_array_t *rrs;		/*!< List of preselected RRs to be validated. */
	knot_section_t section_id;	/*!< Section to work with. */
	knot_rrset_t *keys;		/*!< DNSKEY RRSet; TTLs may get lowered when validating this set. */
        const knot_dname_t *zone_name;	/*!< Name of the zone containing the RRSIG RRSet. */
	uint32_t timestamp;		/*!< Validation time. */
        bool has_nsec3;			/*!< Whether to use NSEC3 validation. */
	uint32_t qry_uid;		/*!< Current query uid. */
	uint32_t flags;			/*!< Output - Flags. */
	uint32_t err_cnt;		/*!< Output - Number of validation failures. */
	uint32_t cname_norrsig_cnt;	/*!< Output - Number of CNAMEs missing RRSIGs. */

	/** Validation result: kr_error() code.
	 *
	 * ENOENT: the usual, no suitable signature found
	 * EAGAIN: encountered a different signer name
	 * +others
	 */
	int result;
	const struct kr_query *log_qry; /*!< The query; just for logging purposes. */
	struct {
		unsigned int matching_name_type;	/*!< Name + type matches */
		unsigned int expired;
		unsigned int notyet;
		unsigned int signer_invalid;		/*!< Signer is not zone apex */
		unsigned int labels_invalid;		/*!< Number of labels in RRSIG */
		unsigned int key_invalid;		/*!< Algorithm/keytag/key owner */
		unsigned int crypto_invalid;
		unsigned int nsec_invalid;
	} rrs_counters;	/*!< Error counters for single RRset validation. */
};

typedef struct kr_rrset_validation_ctx kr_rrset_validation_ctx_t;

/**
 * Validate RRSet.
 * @param vctx    Pointer to validation context.
 * @param covered RRSet covered by a signature. It must be in canonical format.
 * 		  Its TTL may get lowered.
 * @return        0 or kr_error() code, same as vctx->result (see its docs).
 */
int kr_rrset_validate(kr_rrset_validation_ctx_t *vctx, knot_rrset_t *covered);

/**
 * Return true iff the RRset contains at least one usable DS.  See RFC6840 5.2.
 */
KR_EXPORT KR_PURE
bool kr_ds_algo_support(const knot_rrset_t *ta);

/**
 * Check whether the DNSKEY rrset matches the supplied trust anchor RRSet.
 *
 * @param vctx  Pointer to validation context.  Note that TTL of vctx->keys may get lowered.
 * @param sigs  RRSIGs for this DNSKEY set
 * @param ta    Trusted DS RRSet against which to validate the DNSKEY RRSet.
 * @return      0 or error code, same as vctx->result.
 */
int kr_dnskeys_trusted(kr_rrset_validation_ctx_t *vctx, const knot_rdataset_t *sigs,
			const knot_rrset_t *ta);

/** Return true if the DNSKEY can be used as a ZSK.  */
KR_EXPORT KR_PURE
bool kr_dnssec_key_zsk(const uint8_t *dnskey_rdata);

/** Return true if the DNSKEY indicates being KSK (=> has SEP).  */
KR_EXPORT KR_PURE
bool kr_dnssec_key_ksk(const uint8_t *dnskey_rdata);

/** Return true if the DNSKEY is revoked. */
KR_EXPORT KR_PURE
bool kr_dnssec_key_revoked(const uint8_t *dnskey_rdata);

/** Return DNSKEY tag.
  * @param rrtype RR type (either DS or DNSKEY are supported)
  * @param rdata  Key/digest RDATA.
  * @param rdlen  RDATA length.
  * @return Key tag (positive number), or an error code
  */
KR_EXPORT KR_PURE
int kr_dnssec_key_tag(uint16_t rrtype, const uint8_t *rdata, size_t rdlen);

/** Return 0 if the two keys are identical.
  * @note This compares RDATA only, algorithm and public key must match.
  * @param key_a_rdata First key RDATA
  * @param key_a_rdlen First key RDATA length
  * @param key_b_rdata Second key RDATA
  * @param key_b_rdlen Second key RDATA length
  * @return 0 if they match or an error code
  */
KR_EXPORT KR_PURE
int kr_dnssec_key_match(const uint8_t *key_a_rdata, size_t key_a_rdlen,
                        const uint8_t *key_b_rdata, size_t key_b_rdlen);

/* Opaque DNSSEC key struct; forward declaration from libdnssec. */
struct dnssec_key;

/**
 * Construct a DNSSEC key.
 * @param key   Pointer to be set to newly created DNSSEC key.
 * @param kown  DNSKEY owner name.
 * @param rdata DNSKEY RDATA
 * @param rdlen DNSKEY RDATA length
 * @return 0 or error code; in particular: DNSSEC_INVALID_KEY_ALGORITHM
 */
int kr_dnssec_key_from_rdata(struct dnssec_key **key, const knot_dname_t *kown, const uint8_t *rdata, size_t rdlen);

/**
 * Frees the DNSSEC key.
 * @param key Pointer to freed key.
 */
void kr_dnssec_key_free(struct dnssec_key **key);

/**
 * Checks whether NSEC/NSEC3 RR selected by iterator matches the supplied name and type.
 * @param rrs     Records selected by iterator.
 * @param qry_uid Query unique identifier where NSEC/NSEC3 belongs to.
 * @param name    Name to be checked.
 * @param type    Type to be checked.
 * @return        0 or error code.
 */
int kr_dnssec_matches_name_and_type(const ranked_rr_array_t *rrs, uint32_t qry_uid,
				    const knot_dname_t *name, uint16_t type);


/* Simple validator API.  Main use case: prefill module, i.e. RRs from a zone file. */

/** Opaque context for simple validator. */
struct kr_svldr_ctx;
/**
 * Create new context for validating within a given zone.
 *
 * - `ds` is assumed to be trusted, and it's used to validate `dnskey+dnskey_sigs`.
 * - The TTL of `dnskey` may get trimmed.
 * - The insides are placed on malloc heap (use _free_ctx).
 * - `err_ctx` is optional, for use when error happens (but avoid the inside pointers)
 */
KR_EXPORT
struct kr_svldr_ctx * kr_svldr_new_ctx(const knot_rrset_t *ds, knot_rrset_t *dnskey,
		const knot_rdataset_t *dnskey_sigs, uint32_t timestamp,
		kr_rrset_validation_ctx_t *err_ctx);
/** Free the context.  Passing NULL is OK. */
KR_EXPORT
void kr_svldr_free_ctx(struct kr_svldr_ctx *ctx);
/**
 * Validate an RRset with the associated signatures; assume no wildcard expansions.
 *
 * - It's caller's responsibility that rrsigs have matching owner, class and type.
 * - The TTL of `rrs` may get trimmed.
 * - If it's a wildcard other than in its simple `*.` form, it may fail to validate.
 * - More generally, non-existence proofs are not supported.
 * @return  0 or kr_error() code, same as kr_rrset_validation_ctx::result (see its docs).
 */
KR_EXPORT
int kr_svldr_rrset(knot_rrset_t *rrs, const knot_rdataset_t *rrsigs,
			struct kr_svldr_ctx *ctx);

