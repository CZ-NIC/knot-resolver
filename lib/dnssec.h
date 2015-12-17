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

#pragma once

#include "lib/defines.h"
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

/** Opaque DNSSEC key pointer. */
struct dseckey;

/**
 * Validate RRSet.
 * @param pkt        Packet to be validated.
 * @param section_id Section to work with.
 * @param covered    RRSet covered by a signature. It must be in canonical format.
 * @param keys       DNSKEY RRSet.
 * @param zone_name  Name of the zone containing the RRSIG RRSet.
 * @param timestamp  Validation time.
 * @param has_nsec3  Whether to use NSEC3 validation.
 * @return           0 or error code.
 */
int kr_rrset_validate(const knot_pkt_t *pkt, knot_section_t section_id,
                      const knot_rrset_t *covered, const knot_rrset_t *keys,
                      const knot_dname_t *zone_name, uint32_t timestamp,
                      bool has_nsec3);

/**
 * Validate RRSet using a specific key.
 * @param pkt        Packet to be validated.
 * @param section_id Section to work with.
 * @param covered    RRSet covered by a signature. It must be in canonical format.
 * @param keys       DNSKEY RRSet.
 * @param key_pos    Position of the key to be validated with.
 * @param key        Key to be used to validate. If NULL, then key from DNSKEY RRSet is used.
 * @param zone_name  Name of the zone containing the RRSIG RRSet.
 * @param timestamp  Validation time.
 * @param has_nsec3  Whether to use NSEC3 validation.
 * @return           0 or error code.
 */
int kr_rrset_validate_with_key(const knot_pkt_t *pkt, knot_section_t section_id,
                               const knot_rrset_t *covered, const knot_rrset_t *keys,
                               size_t key_pos, const struct dseckey *key,
                               const knot_dname_t *zone_name, uint32_t timestamp,
                               bool has_nsec3);

/**
 * Check whether the DNSKEY rrset matches the supplied trust anchor RRSet.
 * @param pkt        Packet to be validated.
 * @param section_id Section to work with.
 * @param keys       DNSKEY RRSet to check.
 * @param ta         Trust anchor RRSet against which to validate the DNSKEY RRSet.
 * @param zone_name  Name of the zone containing the RRSet.
 * @param timestamp  Time stamp.
 * @param has_nsec3  Whether to use NSEC3 validation.
 * @return     0 or error code.
 */
int kr_dnskeys_trusted(const knot_pkt_t *pkt, knot_section_t section_id, const knot_rrset_t *keys,
                       const knot_rrset_t *ta, const knot_dname_t *zone_name, uint32_t timestamp,
                       bool has_nsec3);

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

/**
 * Construct a DNSSEC key.
 * @param key   Pointer to be set to newly created DNSSEC key.
 * @param kown  DNSKEY owner name.
 * @param rdata DNSKEY RDATA
 * @param rdlen DNSKEY RDATA length
 */
int kr_dnssec_key_from_rdata(struct dseckey **key, const knot_dname_t *kown, const uint8_t *rdata, size_t rdlen);

/**
 * Frees the DNSSEC key.
 * @param key Pointer to freed key.
 */
void kr_dnssec_key_free(struct dseckey **key);
