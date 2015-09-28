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

#include <libknot/internal/mempattern.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrset.h>

#include "lib/generic/map.h"

/* Stash key flags */
#define KEY_FLAG_NO 0x01
#define KEY_FLAG_RRSIG 0x02
#define KEY_FLAG_SET(key, flag) key[0] = (flag);
#define KEY_COVERING_RRSIG(key) (key[0] & KEY_FLAG_RRSIG)

/**
 * Merges RRSets with matching owner name and type together.
 * @note RRSIG RRSets are merged according the type covered fields.
 * @param pkt   Packet which the rset belongs to.
 * @param stash Holds the merged RRSets.
 * @param rr    RRSet to be added.
 * @param pool  Memory pool.
 * @return      0 or an error
 */
int stash_add(const knot_pkt_t *pkt, map_t *stash, const knot_rrset_t *rr, mm_ctx_t *pool);
