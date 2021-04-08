/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

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

/** Pointer to the singleton worker.  NULL if not initialized. */
KR_EXPORT extern struct worker_ctx *the_worker;

/** Create and initialize the worker.
 * \return error code (ENOMEM) */
int worker_init(struct engine *engine, int worker_count);

/** Destroy the worker (free memory). */
void worker_deinit(void);

/**
 * Process an incoming packet (query from a client or answer from upstream).
 *
 * @param session  session the packet came from, or NULL (not from network)
 * @param peer     address the packet came from, or NULL (not from network)
 * @param eth_*    MAC addresses or NULL (they're useful for XDP)
 * @param pkt      the packet, or NULL (an error from the transport layer)
 * @return 0 or an error code
 */
int worker_submit(struct session *session,
		  const struct sockaddr *peer, const struct sockaddr *dst_addr,
		  const uint8_t *eth_from, const uint8_t *eth_to, knot_pkt_t *pkt);

/**
 * End current DNS/TCP session, this disassociates pending tasks from this session
 * which may be freely closed afterwards.
 */
int worker_end_tcp(struct session *session);

KR_EXPORT knot_pkt_t *worker_resolve_mk_pkt_dname(knot_dname_t *qname, uint16_t qtype, uint16_t qclass,
				   const struct kr_qflags *options);

/**
 * Create a packet suitable for worker_resolve_start().  All in malloc() memory.
 */
KR_EXPORT knot_pkt_t *
worker_resolve_mk_pkt(const char *qname_str, uint16_t qtype, uint16_t qclass,
			const struct kr_qflags *options);

/**
 * Start query resolution with given query.
 *
 * @return task or NULL
 */
KR_EXPORT struct qr_task *
worker_resolve_start(knot_pkt_t *query, struct kr_qflags options);

/**
 * Execute a request with given query.
 * It expects task to be created with \fn worker_resolve_start.
 *
 * @return 0 or an error code
 */
KR_EXPORT int worker_resolve_exec(struct qr_task *task, knot_pkt_t *query);

/** @return struct kr_request associated with opaque task */
struct kr_request *worker_task_request(struct qr_task *task);

int worker_task_step(struct qr_task *task, const struct sockaddr *packet_source,
		     knot_pkt_t *packet);

int worker_task_numrefs(const struct qr_task *task);

/** Finalize given task */
int worker_task_finalize(struct qr_task *task, int state);

void worker_task_complete(struct qr_task *task);

void worker_task_ref(struct qr_task *task);

void worker_task_unref(struct qr_task *task);

void worker_task_timeout_inc(struct qr_task *task);

int worker_add_tcp_connected(struct worker_ctx *worker,
			     const struct sockaddr *addr,
			     struct session *session);
int worker_del_tcp_connected(struct worker_ctx *worker,
			     const struct sockaddr *addr);
int worker_del_tcp_waiting(struct worker_ctx *worker,
			   const struct sockaddr* addr);
struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr* addr);
struct session* worker_find_tcp_connected(struct worker_ctx *worker,
					       const struct sockaddr* addr);
knot_pkt_t *worker_task_get_pktbuf(const struct qr_task *task);

struct request_ctx *worker_task_get_request(struct qr_task *task);

struct session *worker_request_get_source_session(struct request_ctx *);

void worker_request_set_source_session(struct request_ctx *, struct session *session);

uint16_t worker_task_pkt_get_msgid(struct qr_task *task);
void worker_task_pkt_set_msgid(struct qr_task *task, uint16_t msgid);
uint64_t worker_task_creation_time(struct qr_task *task);
void worker_task_subreq_finalize(struct qr_task *task);
bool worker_task_finished(struct qr_task *task);

/** To be called after sending a DNS message.  It mainly deals with cleanups. */
int qr_task_on_send(struct qr_task *task, const uv_handle_t *handle, int status);

/** Various worker statistics.  Sync with wrk_stats() */
struct worker_stats {
	size_t queries;     /**< Total number of requests (from clients and internal ones). */
	size_t concurrent;  /**< The number of requests currently in processing. */
	size_t rconcurrent; /*< TODO: remove?  I see no meaningful difference from .concurrent. */
	size_t dropped;     /**< The number of requests dropped due to being badly formed.  See #471. */

	size_t timeout; /**< Number of outbound queries that timed out. */
	size_t udp;  /**< Number of outbound queries over UDP. */
	size_t tcp;  /**< Number of outbound queries over TCP (excluding TLS). */
	size_t tls;  /**< Number of outbound queries over TLS. */
	size_t ipv4; /**< Number of outbound queries over IPv4.*/
	size_t ipv6; /**< Number of outbound queries over IPv6. */

	size_t err_udp;  /**< Total number of write errors for UDP transport. */
	size_t err_tcp;  /**< Total number of write errors for TCP transport. */
	size_t err_tls;  /**< Total number of write errors for TLS transport. */
	size_t err_http;  /**< Total number of write errors for HTTP(S) transport. */
};

/** @cond internal */

/** Number of request within timeout window. */
#define MAX_PENDING 4

/** Maximum response time from TCP upstream, milliseconds */
#define MAX_TCP_INACTIVITY (KR_RESOLVE_TIME_LIMIT + KR_CONN_RTT_MAX)

#ifndef RECVMMSG_BATCH /* see check_bufsize() */
#define RECVMMSG_BATCH 1
#endif

/** Freelist of available mempools. */
typedef array_t(struct mempool *) mp_freelist_t;

/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

/** List of HTTP header names. */
typedef array_t(const char *) doh_headerlist_t;

/** \details Worker state is meant to persist during the whole life of daemon. */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	int count;  /** unreliable, does not count systemd instance, do not use */
	int vars_table_ref;
	unsigned tcp_pipeline_max;

	/** Addresses to bind for outgoing connections or AF_UNSPEC. */
	struct sockaddr_in out_addr4;
	struct sockaddr_in6 out_addr6;

	uint8_t wire_buf[RECVMMSG_BATCH * KNOT_WIRE_MAX_PKTSIZE];

	struct worker_stats stats;

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
	knot_mm_t pkt_pool;
	unsigned int next_request_uid;

	/* HTTP Headers for DoH. */
	doh_headerlist_t doh_qry_headers;
};

/** @endcond */

