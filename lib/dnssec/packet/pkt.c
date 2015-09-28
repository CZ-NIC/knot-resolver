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

#include <libknot/internal/consts.h>

#include "lib/dnssec/packet/pkt.h"

/**
 * Search in section for given type.
 * @param sec  Packet section.
 * @param type Type to search for.
 * @return     True if found.
 */
static bool section_has_type(const knot_pktsection_t *sec, uint16_t type)
{
	if (!sec) {
		return false;
	}

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type == type) {
			return true;
		}
	}

	return false;
}

bool _knot_pkt_has_type(const knot_pkt_t *pkt, uint16_t type)
{
	if (!pkt) {
		return false;
	}

	if (section_has_type(knot_pkt_section(pkt, KNOT_ANSWER), type)) {
		return true;
	}
	if (section_has_type(knot_pkt_section(pkt, KNOT_AUTHORITY), type)) {
		return true;
	}
	return section_has_type(knot_pkt_section(pkt, KNOT_ADDITIONAL), type);
}
