/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "daemon/engine.h"
#include "lib/generic/array.h"
#include "lib/generic/map.h"


/** Worker state (opaque). */
struct worker_ctx;
/** Worker callback */
typedef void (*worker_cb_t)(struct worker_ctx *worker, struct kr_request *req, void *baton);

/** Create and initialize the worker. */
struct worker_ctx *worker_create(struct engine *engine, knot_mm_t *pool,
		int worker_id, int worker_count);

/**
 * Process incoming packet (query or answer to subrequest).
 * @return 0 or an error code
 */
int worker_submit(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query,
		const struct sockaddr* addr);

/**
 * Process incoming DNS/TCP message fragment(s).
 * If the fragment contains only a partial message, it is buffered.
 * If the fragment contains a complete query or completes current fragment, execute it.
 * @return the number of newly-completed requests (>=0) or an error code
 */
int worker_process_tcp(struct worker_ctx *worker, uv_stream_t *handle,
		const uint8_t *msg, ssize_t len);

/**
 * End current DNS/TCP session, this disassociates pending tasks from this session
 * which may be freely closed afterwards.
 */
int worker_end_tcp(struct worker_ctx *worker, uv_handle_t *handle);

/**
 * Schedule query for resolution.
 * @return 0 or an error code
 */
int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, unsigned options,
		worker_cb_t on_complete, void *baton);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);


/** @cond internal */

/** Number of request within timeout window. */
#define MAX_PENDING KR_NSREP_MAXADDR

/** Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;

/** \details Worker state is meant to persist during the whole life of daemon. */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	int id;
	int count;
	unsigned tcp_pipeline_max;

	/** Addresses to bind for outgoing connections or AF_UNSPEC. */
	struct sockaddr_in out_addr4;
	struct sockaddr_in6 out_addr6;

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

	map_t outgoing;
	mp_freelist_t pool_mp;
	mp_freelist_t pool_ioreq;
	mp_freelist_t pool_sessions;
	knot_mm_t pkt_pool;
};

/** Query resolution task. */
struct qr_task
{
	struct kr_request req;
	struct worker_ctx *worker;
	struct session *session;
	knot_pkt_t *pktbuf;
	array_t(struct qr_task *) waiting;
	uv_handle_t *pending[MAX_PENDING];
	uint16_t pending_count;
	uint16_t addrlist_count;
	uint16_t addrlist_turn;
	uint16_t timeouts;
	uint16_t iter_count;
	uint16_t bytes_remaining;
	struct sockaddr *addrlist;
	uv_timer_t *timeout;
	worker_cb_t on_complete;
	void *baton;
	struct {
		union inaddr addr;
		union inaddr dst_addr;
		uv_handle_t *handle;
	} source;
	uint32_t refs;
	bool finished : 1;
	bool leading  : 1;
};

/** @endcond */

