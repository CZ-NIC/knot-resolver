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

#include <libknot/packet/pkt.h>
#include "context.h"

/*!
 * \brief Resolve an input query and produce a packet with an answer.
 * \note The function doesn't change the packet question or message ID.
 * \param ctx resolution context
 * \param answer answer packet to be written
 * \param qname resolved query name
 * \param qclass resolved query class
 * \param qtype resolved query type
 * \return KNOT_E*
 */
int kr_resolve(struct kr_context* ctx, knot_pkt_t *answer,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);
