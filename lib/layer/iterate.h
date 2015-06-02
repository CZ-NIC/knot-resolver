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

#include "lib/layer.h"
#include "lib/rplan.h"

/* Packet classification. */
enum {
	PKT_NOERROR   = 1 << 0, /* Positive response */
	PKT_NODATA    = 1 << 1, /* No data response */
	PKT_NXDOMAIN  = 1 << 2, /* Negative response */
	PKT_REFUSED   = 1 << 3, /* Refused response */
	PKT_ERROR     = 1 << 4  /* Bad message */
};

/** Classify response by type. */
int kr_response_classify(knot_pkt_t *pkt);

/* Processing module implementation. */
const knot_layer_api_t *iterate_layer(struct kr_module *module);
