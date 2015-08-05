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
 * Check the non-existence of an exact/closer match according to RFC4035 5.4, bullet 2.
 * @note No RRSIGs are checked.
 * @param nsec NSEC RRSet containing a single record.
 * @param name Domain name checked against the NSEC record.
 * @return     0 or error code.
 */
int kr_nsec_nomatch_validate(const knot_rrset_t *nsec, const knot_dname_t *name);

/**
 * Authenticated denial of existence according to RFC4035 5.4.
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param name       Queried domain name.
 * @param type       Queried type.
 * @return           0 or error code.
 */
int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *name, uint16_t type, mm_ctx_t *pool);
