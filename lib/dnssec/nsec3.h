/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <libknot/packet/pkt.h>

/**
 * Name error response check (RFC5155 7.2.2).
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @return           0 or error code.
 */
int kr_nsec3_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                       const knot_dname_t *sname);

/**
 * Wildcard answer response check (RFC5155 7.2.6).
 * @param pkt          Packet structure to be processed.
 * @param section_id   Packet section to be processed.
 * @param sname        Name to be checked.
 * @param trim_to_next Number of labels to remove to obtain next closer name.
 * @return             0 or error code.
 */
int kr_nsec3_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *sname, int trim_to_next);

/**
 * Authenticated denial of existence according to RFC5155 8.5 and 8.7.
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Queried domain name.
 * @param stype      Queried type.
 * @return           0 or error code:
 *                   DNSSEC_NOT_FOUND - neither ds nor nsec records
 *                   were not found.
 *                   DNSSEC_OUT_OF_RANGE - denial of existence can't be proven
 *                   due to opt-out, otherwise - bogus.
 */
int kr_nsec3_no_data(const knot_pkt_t *pkt, knot_section_t section_id,
                     const knot_dname_t *sname, uint16_t stype);

/**
 * Referral to unsigned subzone check (RFC5155 8.9).
 * @note 	     No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @return           0 or error code:
 *                   DNSSEC_OUT_OF_RANGE - denial of existence can't be proven
 *                   due to opt-out.
 *                   EEXIST - ds record was found.
 *                   EINVAL - bogus.
 */
int kr_nsec3_ref_to_unsigned(const knot_pkt_t *pkt);
