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

#include <libknot/descriptor.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/aaaa.h>
#include <libknot/internal/sockaddr.h>

#include "lib/defines.h"

/*!
 * \brief Convert A/AAAA RRs to address with DNS port.
 * \param ss address storage
 * \param rr resource record
 * \return KNOT_E*
 */
static inline int kr_rrset_to_addr(struct sockaddr_storage *ss, const knot_rrset_t *rr)
{
	/* Retrieve an address from glue record. */
	switch(rr->type) {
	case KNOT_RRTYPE_A:
		knot_a_addr(&rr->rrs, 0, (struct sockaddr_in *)ss);
		break;
	case KNOT_RRTYPE_AAAA:
		knot_aaaa_addr(&rr->rrs, 0, (struct sockaddr_in6 *)ss);
		break;
	default:
		return KNOT_EINVAL;
	}

	sockaddr_port_set((struct sockaddr_storage *)ss, KR_DNS_PORT);
	return KNOT_EOK;
}
