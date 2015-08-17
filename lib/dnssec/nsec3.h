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
 * No data response check (RFC5155 7.2.3 and 7.2.4).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
int kr_nsec3_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                    const knot_dname_t *sname, uint16_t stype);

/**
 * Wildcard no data response check (RFC5155 7.2.5).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
int kr_nsec3_wildcard_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                             const knot_dname_t *sname, uint16_t stype);
