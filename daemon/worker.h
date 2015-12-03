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
#include "lib/generic/map.h"

/* @cond internal Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;
/* @endcond */

/**
 * Query resolution worker.
 */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
#if __linux__
	uint8_t wire_buf[RECVMMSG_BATCH * KNOT_WIRE_MAX_PKTSIZE];
#else
	uint8_t wire_buf[KNOT_WIRE_MAX_PKTSIZE];
#endif
	struct {
		size_t concurrent;
		size_t udp;
		size_t tcp;
		size_t ipv4;
		size_t ipv6;
		size_t queries;
		size_t dropped;
		size_t timeout;
	} stats;
	map_t outstanding;
	mp_freelist_t pools;
	mp_freelist_t ioreqs;
	mm_ctx_t pkt_pool;
};

/* Worker callback */
typedef void (*worker_cb_t)(struct worker_ctx *worker, struct kr_request *req, void *baton);

/**
 * Process incoming packet (query or answer to subrequest).
 * @return 0 or an error code
 */
int worker_exec(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr* addr);

/**
 * Process incoming DNS/TCP message fragment.
 * If the fragment contains only a partial message, it is buffered.
 * If the fragment contains a complete query or completes current fragment, execute it.
 * @return 0, number of bytes remaining to assemble, or an error code
 */
int worker_process_tcp(struct worker_ctx *worker, uv_handle_t *handle, const uint8_t *msg, size_t len);

/**
 * Schedule query for resolution.
 * @return 0 or an error code
 */
int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, unsigned options, worker_cb_t on_complete, void *baton);

/** Reserve worker buffers */
int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);
