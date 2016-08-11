/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/**
 * @brief Checks cookies of inbound requests.
 * @param ctx layer context
 * @param module_param module parameters
 * @return layer state
 */
int check_request(knot_layer_t *ctx, void *module_param);

/**
 * @brief Checks cookies of received responses.
 * @param ctx layer context
 * @param pkt response packet
 * @return layer state
 */
int check_response(knot_layer_t *ctx, knot_pkt_t *pkt);
