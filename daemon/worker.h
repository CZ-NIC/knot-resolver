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

#include <uv.h>

#include <libknot/internal/mempattern.h>
#include "lib/resolve.h"

struct worker_ctx {
	struct kr_context resolve;
	mm_ctx_t *pool;
};

int worker_init(struct worker_ctx *worker, mm_ctx_t *mm);
void worker_deinit(struct worker_ctx *worker);
void worker_start(uv_udp_t *req, struct worker_ctx *worker);
void worker_stop(uv_udp_t *req);
