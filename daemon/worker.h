/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "daemon/engine.h"
#include "lib/generic/array.h"
#include "lib/generic/trie.h"
#include "daemon/quic_conn.h"

/** Query resolution task (opaque). */
struct qr_task;
/** Worker state. */
struct worker_ctx;
/** Transport session (opaque). */
struct session2;
/** Data about the communication (defined in io.h). */
struct comm_info;

/** Pointer to the singleton worker.  NULL if not initialized. */
KR_EXPORT extern struct worker_ctx *the_worker;

/** Create and initialize the worker.
 * \return error code (ENOMEM) */
int worker_init(void);

/** Destroy the worker (free memory). */
void worker_deinit(void);

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

knot_pkt_t *worker_task_get_pktbuf(const struct qr_task *task);

struct kr_transport *worker_task_get_transport(struct qr_task *task);

/** Note: source session is NULL in case the request hasn't come over network. */
KR_EXPORT struct session2 *worker_request_get_source_session(const struct kr_request *req);

uint16_t worker_task_pkt_get_msgid(struct qr_task *task);
void worker_task_pkt_set_msgid(struct qr_task *task, uint16_t msgid);
uint64_t worker_task_creation_time(struct qr_task *task);
void worker_task_subreq_finalize(struct qr_task *task);
bool worker_task_finished(struct qr_task *task);

/** To be called after sending a DNS message.  It mainly deals with cleanups. */
int qr_task_on_send(struct qr_task *task, struct session2 *s, int status);

/* Attempt to send out waiting tasks, waiting tasks are usually the result
 * of max_streams_bidi limits for the connection */
int send_waiting_subsession(struct session2 *session);

/* Handles QUIC handshake timeout.
 * Unlike other transport protocols client-side DoQ can reach a state where:
 *   - QUIC connection session exists
 *   - session's waitinglist contains a task
 *   - QUIC stream session does NOT exist
 *   - handshake timed-out
 * in order to provide uniform logging across all transport protocols
 * this function logs the information usually written by
 * pl_dns_stream_connection_fail (which in this situation is in
 * a as of yet non-existend session, and cannot be reached). */
void quic_handshake_timeout(struct session2 *session,
		enum kr_selection_error sel_err);

/* similar to on connect used by TCP */
void doq_on_connect(struct pl_quic_conn_sess_data *conn, int status);

void worker_remove_quic_conn(struct session2 *session, const struct sockaddr *addr);

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
	size_t quic; /**< Number of outbound queries over quic. */
	size_t ipv4; /**< Number of outbound queries over IPv4.*/
	size_t ipv6; /**< Number of outbound queries over IPv6. */

	size_t err_udp;  /**< Total number of write errors for UDP transport. */
	size_t err_tcp;  /**< Total number of write errors for TCP transport. */
	size_t err_tls;  /**< Total number of write errors for TLS transport. */
	size_t err_http;  /**< Total number of write errors for HTTP(S) transport. */
	size_t err_quic;  /**< Total number of write errors for QUIC transport. */
};

/** @cond internal */

/** Number of request within timeout window. */
#define MAX_PENDING 4

/** Maximum response time from TCP upstream, milliseconds */
#define MAX_TCP_INACTIVITY (KR_RESOLVE_TIME_LIMIT + KR_CONN_RTT_MAX)

#ifndef RECVMMSG_BATCH /* see check_bufsize() */
#define RECVMMSG_BATCH 1
#endif

/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

/** List of HTTP header names. */
typedef array_t(const char *) doh_headerlist_t;

/** \details Worker state is meant to persist during the whole life of daemon. */
struct worker_ctx {
	uv_loop_t *loop;
	int count;  /** unreliable, does not count systemd instance, do not use */
	int vars_table_ref;
	unsigned tcp_pipeline_max;

	/** Addresses to bind for outgoing connections or AF_UNSPEC. */
	struct sockaddr_in out_addr4;
	struct sockaddr_in6 out_addr6;

	struct worker_stats stats;

	bool too_many_open;
	size_t rconcurrent_highwatermark;
	/** List of active outbound TCP sessions */
	trie_t *tcp_connected;
	/** List of outbound TCP sessions waiting to be accepted */
	trie_t *tcp_waiting;
	/** List of active outbound QUIC sessions */
	trie_t *quic_connected;
	/** List of outbound QUIC sessions waiting to be accepted */
	trie_t *quic_waiting;
	/** Subrequest leaders (struct qr_task*), indexed by qname+qtype+qclass. */
	trie_t *subreq_out;
	knot_mm_t pkt_pool;
	unsigned int next_request_uid;

	/* session for all outgoing DoQ requests. */
	struct session2 *doq_out_session;

	/* HTTP Headers for DoH. */
	doh_headerlist_t doh_qry_headers;
};

/** @endcond */

