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
#include "lib/generic/array.h"

/* @cond internal Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;
/* @endcond */

/**
 * Query resolution worker.
 */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	mm_ctx_t *mm;
#if __linux__
	uint8_t wire_buf[RECVMMSG_BATCH * KNOT_WIRE_MAX_PKTSIZE];
#else
	uint8_t wire_buf[KNOT_WIRE_MAX_PKTSIZE];
#endif
	struct {
		size_t concurrent;
		size_t udp;
		size_t tcp;
	} stats;
	mp_freelist_t pools;
	mp_freelist_t ioreqs;
};

/**
 * Process incoming packet (query or answer to subrequest).
 * @return 0 or an error code
 */
int worker_exec(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr* addr);

/**
 * Schedule query for resolution.
 * @return 0 or an error code
 */
int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query);

/** Reserve worker buffers */
int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);
