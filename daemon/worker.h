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

#include "daemon/engine.h"
#include "lib/generic/array.h"
#include "lib/generic/map.h"

/** @internal Number of request within timeout window. */
#define MAX_PENDING (KR_NSREP_MAXADDR + (KR_NSREP_MAXADDR / 2))

/** @cond internal Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;

/**
 * Query resolution worker.
 */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	int id;
	int count;
	unsigned tcp_pipeline_max;
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
	map_t outstanding;
	mp_freelist_t pool_mp;
	mp_freelist_t pool_ioreq;
	mp_freelist_t pool_sessions;
	knot_mm_t pkt_pool;
};

/* Worker callback */
typedef void (*worker_cb_t)(struct worker_ctx *worker, struct kr_request *req, void *baton);

/** @internal Query resolution task. */
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
		union {
			struct sockaddr_in ip4;
			struct sockaddr_in6 ip6;
		} addr;
		union {
			struct sockaddr_in ip4;
			struct sockaddr_in6 ip6;
		} dst_addr;
		uv_handle_t *handle;
	} source;
	uint32_t refs;
	bool finished : 1;
	bool leading  : 1;
};
/* @endcond */

/**
 * Process incoming packet (query or answer to subrequest).
 * @return 0 or an error code
 */
int worker_submit(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr* addr);

/**
 * Process incoming DNS/TCP message fragment(s).
 * If the fragment contains only a partial message, it is buffered.
 * If the fragment contains a complete query or completes current fragment, execute it.
 * @return 0 or an error code
 */
int worker_process_tcp(struct worker_ctx *worker, uv_handle_t *handle, const uint8_t *msg, ssize_t len);

/**
 * End current DNS/TCP session, this disassociates pending tasks from this session
 * which may be freely closed afterwards.
 */
int worker_end_tcp(struct worker_ctx *worker, uv_handle_t *handle);


/**
 * Schedule query for resolution.
 * @return 0 or an error code
 */
int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, unsigned options, worker_cb_t on_complete, void *baton);

/** Reserve worker buffers */
int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);
