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

#include <libknot/internal/consts.h>
#include <libknot/internal/mempattern.h>
#include <libknot/packet/pkt.h>

/**
 * Check whether bitmap contains given type.
 * @param bm      Bitmap.
 * @patam bm_size Bitmap size.
 * @param type    RR type to search for.
 * @return        True if bitmap contains type.
 */
bool kr_nsec_bitmap_contains_type(const uint8_t *bm, uint16_t bm_size, uint16_t type);

/**
 * Name error response check (RFC4035 3.1.3.2; RFC4035 5.4, bullet 2).
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param pool
 * @return           0 or error code.
 */
int kr_nsec_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                      const knot_dname_t *sname, mm_ctx_t *pool);

/**
 * No data response check (RFC4035 3.1.3.1; RFC4035 5.4, bullet 1).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
int kr_nsec_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                   const knot_dname_t *sname, uint16_t stype);

/**
 * Wildcard no data response check (RFC4035 3.1.3.4).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
int kr_nsec_wildcard_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *sname, uint16_t stype);

/**
 * Wildcard answer response check (RFC4035 3.1.3.3).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @return           0 or error code.
 */
int kr_nsec_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                           const knot_dname_t *sname);

/**
 * Authenticated denial of existence according to RFC4035 5.4.
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Queried domain name.
 * @param stype      Queried type.
 * @return           0 or error code.
 */
int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *sname, uint16_t stype, mm_ctx_t *pool);
