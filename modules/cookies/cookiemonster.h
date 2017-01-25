/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <libknot/packet/pkt.h>

#include "lib/layer.h"

/** Checks cookies of inbound requests.  It's for kr_layer_api_t::begin. */
int check_request(kr_layer_t *ctx);

/** Checks cookies of received responses.  It's for kr_layer_api_t::consume. */
int check_response(kr_layer_t *ctx, knot_pkt_t *pkt);
