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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

/* Processing API has been removed from libknot in latest versions. */

#include <libknot/packet/pkt.h>
#include <libknot/mm_ctx.h>

/*! Layer processing states.
 *  Each state represents the state machine transition,
 *  and determines readiness for the next action.
 */
enum knot_layer_state {
	KNOT_STATE_NOOP    = 0,      /*!< N/A */
	KNOT_STATE_CONSUME = 1 << 0, /*!< Consume data. */
	KNOT_STATE_PRODUCE = 1 << 1, /*!< Produce data. */
	KNOT_STATE_DONE    = 1 << 2, /*!< Finished. */
	KNOT_STATE_FAIL    = 1 << 3  /*!< Error. */
};

struct knot_layer_api;
typedef struct knot_layer_api knot_layer_api_t;

struct knot_layer;
typedef struct knot_layer knot_layer_t;

/*! \brief Packet processing context. */
struct knot_layer {
	knot_mm_t *mm;   /* Processing memory context. */
	int state;       /* Bitmap of enum knot_layer_state. */
	void *data;      /* Module specific. */
	const struct knot_layer_api *api;
};

/*! \brief Packet processing module API. */
struct knot_layer_api {
	int (*begin)(knot_layer_t *ctx, void *module_param);
	int (*reset)(knot_layer_t *ctx);
	int (*finish)(knot_layer_t *ctx);
	int (*consume)(knot_layer_t *ctx, knot_pkt_t *pkt);
	int (*produce)(knot_layer_t *ctx, knot_pkt_t *pkt);
	int (*fail)(knot_layer_t *ctx, knot_pkt_t *pkt);
	void *data;
};
