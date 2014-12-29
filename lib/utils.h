/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
