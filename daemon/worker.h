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

#include <gnutls/gnutls.h>

#include "daemon/engine.h"
#include "lib/generic/array.h"
#include "lib/generic/map.h"


/** Query resolution task (opaque). */
struct qr_task;
/** Worker state (opaque). */
struct worker_ctx;
/** Transport session (opaque). */
struct session;
/** Zone import context (opaque). */
struct zone_import_ctx;

/** Create and initialize the worker. */
struct worker_ctx *worker_create(struct engine *engine, knot_mm_t *pool,
		int worker_id, int worker_count);

/**
 * Process an incoming packet (query from a client or answer from upstream).
 *
 * @param worker the singleton worker
 * @param handle socket through which the request came
 * @param query  the packet, or NULL on an error from the transport layer
 * @param addr   the address from which the packet came (or NULL, possibly, on error)
 * @return 0 or an error code
 */
int worker_submit(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query,
		const struct sockaddr* addr);

/**
 * Process incoming DNS message fragment(s) that arrived over a stream (TCP, TLS).
 *
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
 * Start query resolution with given query.
 *
 * @return task or NULL
 */
struct qr_task *worker_resolve_start(struct worker_ctx *worker, knot_pkt_t *query, struct kr_qflags options);

/**
 * Execute a request with given query.
 * It expects task to be created with \fn worker_resolve_start.
 *
 * @return 0 or an error code
 */
int worker_resolve_exec(struct qr_task *task, knot_pkt_t *query);

/** @return struct kr_request associated with opaque task */
struct kr_request *worker_task_request(struct qr_task *task);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);

/** Closes given session */
void worker_session_close(struct session *session);

void *worker_iohandle_borrow(struct worker_ctx *worker);

void worker_iohandle_release(struct worker_ctx *worker, void *h);

ssize_t worker_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len);

ssize_t worker_gnutls_client_push(gnutls_transport_ptr_t h, const void *buf, size_t len);

/** Finalize given task */
int worker_task_finalize(struct qr_task *task, int state);

/** @cond internal */

/** Number of request within timeout window. */
#define MAX_PENDING KR_NSREP_MAXADDR

/** Maximum response time from TCP upstream, milliseconds */
#define MAX_TCP_INACTIVITY (KR_RESOLVE_TIME_LIMIT + KR_CONN_RTT_MAX)

/** Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;

/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

/** Session list. */
typedef array_t(struct session *) qr_sessionlist_t;

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
		size_t rconcurrent;
		size_t udp;
		size_t tcp;
		size_t tls;
		size_t ipv4;
		size_t ipv6;
		size_t queries;
		size_t dropped;
		size_t timeout;
	} stats;

	struct zone_import_ctx* z_import;
	bool too_many_open;
	size_t rconcurrent_highwatermark;
	/** List of active outbound TCP sessions */
	map_t tcp_connected;
	/** List of outbound TCP sessions waiting to be accepted */
	map_t tcp_waiting;
	/** Subrequest leaders (struct qr_task*), indexed by qname+qtype+qclass. */
	trie_t *subreq_out;
	mp_freelist_t pool_mp;
	mp_freelist_t pool_ioreqs;
	mp_freelist_t pool_sessions;
	mp_freelist_t pool_iohandles;
	knot_mm_t pkt_pool;
};

/* @internal Union of some libuv handles for freelist.
 * These have session as their `handle->data` and own it.
 * Subset of uv_any_handle. */
union uv_handles {
	uv_handle_t   handle;
	uv_stream_t   stream;
	uv_udp_t      udp;
	uv_tcp_t      tcp;
	uv_timer_t    timer;
};
typedef union uv_any_handle uv_handles_t;

/* @internal Union of derivatives from uv_req_t libuv request handles for freelist.
 * These have only a reference to the task they're operating on.
 * Subset of uv_any_req. */
union uv_reqs {
	uv_req_t      req;
	uv_shutdown_t sdown;
	uv_write_t    write;
	uv_connect_t  connect;
	uv_udp_send_t send;
};
typedef union uv_reqs uv_reqs_t;

/** @endcond */

