/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <libknot/dname.h>
#include <libknot/rrset.h>
#include <libknot/internal/sockaddr.h>
#include <libknot/internal/namedb/namedb.h>

struct kr_rplan;

/**
 * Current zone cut representation.
*/
struct kr_zonecut {
	knot_dname_t name[KNOT_DNAME_MAXLEN]; /**< Current zone cut */
	knot_dname_t ns[KNOT_DNAME_MAXLEN];   /**< Authoritative NS */
	struct sockaddr_storage addr;         /**< Authoritative NS address. */
};

/**
 * Initialize zone cut with SBELT.
 * @param cut zone cut to be set
 * @return KNOT_E*
 */
int kr_init_zone_cut(struct kr_zonecut *cut);

/**
 * Set zone cut to given name and name server.
 * @note Name server address is blanked.
 * @param cut zone cut to be set
 * @param name zone cut name
 * @param ns   zone cut nameserver
 * @return KNOT_E*
 */
int kr_set_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, const knot_dname_t *ns);

/**
 * Convert A/AAAA RRs to address with DNS port.
 * @param cut zone cut to be set
 * @param rr resource record
 * @param i  index of the set address in the rr
 * @return KNOT_E*
 */
int kr_set_zone_cut_addr(struct kr_zonecut *cut, const knot_rrset_t *rr, uint16_t i);

/**
 * Find the closest enclosing zone cut/nameserver from the cache.
 * @param cut zone cut to be set
 * @param name zone cut name
 * @param txn cache transaction
 * @param timestamp transaction timestamp
 * @return KNOT_E*
 */
int kr_find_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp);

