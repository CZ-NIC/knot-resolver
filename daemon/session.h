/*  Copyright (C) 2018-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/packet/pkt.h>

#include <stdbool.h>
#include <uv.h>

struct qr_task;
struct worker_ctx;
struct session;

struct session_flags {
	bool outgoing : 1;      /**< True: to upstream; false: from a client. */
	bool throttled : 1;     /**< True: data reading from peer is temporarily stopped. */
	bool has_tls : 1;       /**< True: given session uses TLS. */
	bool has_http : 1;      /**< True: given session uses HTTP. */
	bool connected : 1;     /**< True: TCP connection is established. */
	bool closing : 1;       /**< True: session close sequence is in progress. */
	bool wirebuf_error : 1; /**< True: last operation with wirebuf ended up with an error. */
};

/* Allocate new session for a libuv handle.
 * If handle->tyoe is UV_UDP, tls parameter will be ignored. */
struct session *session_new(uv_handle_t *handle, bool has_tls, bool has_http);
/* Clear and free given session. */
void session_free(struct session *session);
/* Clear session. */
void session_clear(struct session *session);
/** Close session. */
void session_close(struct session *session);
/** Start reading from underlying libuv IO handle. */
int session_start_read(struct session *session);
/** Stop reading from underlying libuv IO handle. */
int session_stop_read(struct session *session);

/** List of tasks been waiting for IO. */
/** Check if list is empty. */
bool session_waitinglist_is_empty(const struct session *session);
/** Add task to the end of the list. */
int session_waitinglist_push(struct session *session, struct qr_task *task);
/** Get the first element. */
struct qr_task *session_waitinglist_get(const struct session *session);
/** Get the first element and remove it from the list. */
struct qr_task *session_waitinglist_pop(struct session *session, bool deref);
/** Get the list length. */
size_t session_waitinglist_get_len(const struct session *session);
/** Retry resolution for each task in the list. */
void session_waitinglist_retry(struct session *session, bool increase_timeout_cnt);
/** Finalize all tasks in the list. */
void session_waitinglist_finalize(struct session *session, int status);

/** List of tasks associated with session. */
/** Check if list is empty. */
bool session_tasklist_is_empty(const struct session *session);
/** Get the first element. */
struct qr_task *session_tasklist_get_first(struct session *session);
/** Get the first element and remove it from the list. */
struct qr_task *session_tasklist_del_first(struct session *session, bool deref);
/** Get the list length. */
size_t session_tasklist_get_len(const struct session *session);
/** Add task to the list. */
int session_tasklist_add(struct session *session, struct qr_task *task);
/** Remove task from the list. */
int session_tasklist_del(struct session *session, struct qr_task *task);
/** Remove task with given msg_id, session_flags(session)->outgoing must be true. */
struct qr_task* session_tasklist_del_msgid(const struct session *session, uint16_t msg_id);
/** Find task with given msg_id */
struct qr_task* session_tasklist_find_msgid(const struct session *session, uint16_t msg_id);
/** Finalize all tasks in the list. */
void session_tasklist_finalize(struct session *session, int status);
/** Finalize all expired tasks in the list. */
int session_tasklist_finalize_expired(struct session *session);

/** Both of task lists (associated & waiting). */
/** Check if empty. */
bool session_is_empty(const struct session *session);
/** Get pointer to session flags */
struct session_flags *session_flags(struct session *session);
/** Get pointer to peer address. */
struct sockaddr *session_get_peer(struct session *session);
/** Get pointer to sockname (address of our end, not meaningful for UDP downstream). */
struct sockaddr *session_get_sockname(struct session *session);
/** Get pointer to server-side tls-related data. */
struct tls_ctx *session_tls_get_server_ctx(const struct session *session);
/** Set pointer to server-side tls-related data. */
void session_tls_set_server_ctx(struct session *session, struct tls_ctx *ctx);
/** Get pointer to client-side tls-related data. */
struct tls_client_ctx *session_tls_get_client_ctx(const struct session *session);
/** Set pointer to client-side tls-related data. */
void session_tls_set_client_ctx(struct session *session, struct tls_client_ctx *ctx);
/** Get pointer to that part of tls-related data which has common structure for
 *  server and client. */
struct tls_common_ctx *session_tls_get_common_ctx(const struct session *session);

/** Get pointer to server-side http-related data. */
struct http_ctx *session_http_get_server_ctx(const struct session *session);
/** Set pointer to server-side http-related data. */
void session_http_set_server_ctx(struct session *session, struct http_ctx *ctx);

/** Get pointer to underlying libuv handle for IO operations. */
uv_handle_t *session_get_handle(struct session *session);
struct session *session_get(uv_handle_t *h);

/** Start session timer. */
int session_timer_start(struct session *session, uv_timer_cb cb,
			uint64_t timeout, uint64_t repeat);
/** Restart session timer without changing it parameters. */
int session_timer_restart(struct session *session);
/** Stop session timer. */
int session_timer_stop(struct session *session);

/** Get pointer to the beginning of session wirebuffer. */
uint8_t *session_wirebuf_get_start(struct session *session);
/** Get size of session wirebuffer. */
size_t session_wirebuf_get_size(struct session *session);
/** Get pointer to the beginning of free space in session wirebuffer. */
uint8_t *session_wirebuf_get_free_start(struct session *session);
/** Get amount of free space in session wirebuffer. */
size_t session_wirebuf_get_free_size(struct session *session);
/** Discard all data in session wirebuffer. */
void session_wirebuf_discard(struct session *session);
/** Move all data to the beginning of the buffer. */
void session_wirebuf_compress(struct session *session);
int session_wirebuf_process(struct session *session, const struct sockaddr *peer);
ssize_t session_wirebuf_consume(struct session *session,
				const uint8_t *data, ssize_t len);

/** poison session structure with ASAN. */
void session_poison(struct session *session);
/** unpoison session structure with ASAN. */
void session_unpoison(struct session *session);

knot_pkt_t *session_produce_packet(struct session *session, knot_mm_t *mm);
int session_discard_packet(struct session *session, const knot_pkt_t *pkt);

void session_kill_ioreq(struct session *session, struct qr_task *task);
/** Update timestamp */
void session_touch(struct session *session);
/** Returns either creation time or time of last IO activity if any occurs. */
/* Used for TCP timeout calculation. */
uint64_t session_last_activity(struct session *session);
