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

#include <libknot/internal/mempattern.h>

#include "daemon/engine.h"

/**
 * Query resolution worker.
 */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	mm_ctx_t *mm;
};

/**
 * Resolve query.
 *
 * @param worker
 * @param answer
 * @param query
 * @return 0, error code
 */
int worker_exec(struct worker_ctx *worker, knot_pkt_t *answer, knot_pkt_t *query);
