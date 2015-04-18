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

/** \addtogroup rplan
 * @{
 */

#include <libknot/processing/layer.h>
#include <libknot/packet/pkt.h>

#include "lib/defines.h"

struct kr_context;
struct kr_rplan;

/**
 * Processing module parameters.
 *
 * @note These parameters are passed to each processing layer.
 */
struct kr_layer_param {
	struct kr_context *ctx;
	struct kr_rplan *rplan;
	knot_pkt_t *answer;
};

#ifndef NDEBUG
/** @internal Print a debug message related to resolution. */
 #define QRDEBUG(query, cls, fmt, ...) do { \
    unsigned _ind = 0; \
    for (struct kr_query *q = (query); q; q = q->parent, _ind += 2); \
    fprintf(stderr, "[%s] %*s" fmt, cls, _ind, "", ##  __VA_ARGS__); \
    } while (0)
#else
 #define QRDEBUG(query, cls, fmt, ...)
#endif

/** @} */
