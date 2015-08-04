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

#include <libknot/packet/pkt.h>

/**
 * Initialise cryptographic back-end.
 */
void kr_crypto_init(void);

/**
 * De-initialise cryptographic back-end.
 */
void kr_crypto_cleanup(void);

/**
 * Re-initialise cryptographic back-end.
 * @note Must be called after fork() in the child.
 */
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
 * @return           0 or error code.
 */
int kr_rrset_validate(const knot_pkt_t *pkt, knot_section_t section_id,
                      const knot_rrset_t *covered, const knot_rrset_t *keys,
                      const knot_dname_t *zone_name, uint32_t timestamp);

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
 * @return           0 or error code.
 */
int kr_rrset_validate_with_key(const knot_pkt_t *pkt, knot_section_t section_id,
                               const knot_rrset_t *covered, const knot_rrset_t *keys,
                               size_t key_pos, const struct dseckey *key,
                               const knot_dname_t *zone_name, uint32_t timestamp);

/**
 * Check whether the DNSKEY rrset matches the supplied trust anchor RRSet.
 * @param pkt        Packet to be validated.
 * @param section_id Section to work with.
 * @param keys       DNSKEY RRSet to check.
 * @param ta         Trust anchor RRSet against which to validate the DNSKEY RRSet.
 * @param zone_name  Name of the zone containing the RRSet.
 * @param timestamp  Time stamp.
 * @return     0 or error code.
 */
int kr_dnskeys_trusted(const knot_pkt_t *pkt, knot_section_t section_id, const knot_rrset_t *keys,
                       const knot_rrset_t *ta, const knot_dname_t *zone_name, uint32_t timestamp);

/**
 * Construct a DNSSEC key.
 * @param key    Pointer to be set to newly created DNSSEC key.
 * @param krdata Key RDATA.
 * @param kown   DNSKEY RRSet owner name.
 */
int kr_dnssec_key_from_rdata(struct dseckey **key, const knot_rdata_t *krdata, const knot_dname_t *kown);

/**
 * Frees the DNSSEC key.
 * @param key Pointer to freed key.
 */
void kr_dnssec_key_free(struct dseckey **key);
