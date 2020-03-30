/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/packet/pkt.h>

#include "lib/layer.h"

/** Checks cookies of inbound requests.  It's for kr_layer_api_t::begin. */
int check_request(kr_layer_t *ctx);

/** Checks cookies of received responses.  It's for kr_layer_api_t::consume. */
int check_response(kr_layer_t *ctx, knot_pkt_t *pkt);
