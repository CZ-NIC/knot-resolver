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
#include <libknot/internal/mempattern.h>

#include "lib/resolve.h"

/**
 * Query resolution worker.
 */
struct worker_ctx {
	struct kr_context resolve;
	mm_ctx_t *pool;
};

/**
 * Initialize worker context.
 * @param worker
 * @param mm
 * \return KNOT_E*
 */
int worker_init(struct worker_ctx *worker, mm_ctx_t *mm);

/**
 * Clear worker context.
 * @param worker
 */
void worker_deinit(struct worker_ctx *worker);

/**
 * Resolve query.
 * @param worker
 * @param answer
 * @param query
 * \return KNOT_E*
 */
int worker_exec(struct worker_ctx *worker, knot_pkt_t *answer, knot_pkt_t *query);
