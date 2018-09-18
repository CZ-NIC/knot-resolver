/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <uv.h>
#include "lib/generic/array.h"

struct qr_task;
struct worker_ctx;
struct session;

/* Allocate new session. */
struct session *session_new(void);
/* Clear and free given session. */
void session_free(struct session *session);
/* Clear session. */
void session_clear(struct session *session);
/** Close session. */
void session_close(struct session *session);
/** Start reading from underlying libuv IO handle. */
int session_start_read(struct session *session);

/** List of tasks been waiting for IO. */
/** Check if list is empty. */
bool session_waitinglist_is_empty(const struct session *session);
/** Get the first element. */
struct qr_task *session_waitinglist_get_first(const struct session *session);
/** Get the list length. */
size_t session_waitinglist_get_len(const struct session *session);
/** Add task to the list. */
int session_waitinglist_add(struct session *session, struct qr_task *task);
/** Remove task from the list. */
int session_waitinglist_del(struct session *session, struct qr_task *task);
/** Remove task from the list by index. */
int session_waitinglist_del_index(struct session *session, int index);
/** Retry resolution for each task in the list. */
void session_waitinglist_retry(struct session *session, bool increase_timeout_cnt);
/** Finalize all tasks in the list. */
void session_waitinglist_finalize(struct session *session, int status);

/** List of tasks associated with session. */
/** Check if list is empty. */
bool session_tasklist_is_empty(const struct session *session);
/** Get the first element. */
struct qr_task *session_tasklist_get_first(const struct session *session);
/** Get the list length. */
size_t session_tasklist_get_len(const struct session *session);
/** Add task to the list. */
int session_tasklist_add(struct session *session, struct qr_task *task);
/** Remove task from the list. */
int session_tasklist_del(struct session *session, struct qr_task *task);
/** Remove task from the list by index. */
int session_tasklist_del_index(struct session *session, int index);
/** Find task with given msg_id */
struct qr_task* session_tasklist_find(const struct session *session, uint16_t msg_id);
/** Finalize all tasks in the list. */
void session_tasklist_finalize(struct session *session, int status);

/** Both of task lists (associated & waiting). */
/** Check if empty. */
bool session_is_empty(const struct session *session);
/** Finalize all tasks. */
void session_tasks_finalize(struct session *session, int status);

/** Operations with flags */
bool session_is_outgoing(const struct session *session);
void session_set_outgoing(struct session *session, bool outgoing);
bool session_is_closing(const struct session *session);
void session_set_closing(struct session *session, bool closing);
bool session_is_connected(const struct session *session);
void session_set_connected(struct session *session, bool connected);
bool session_is_throttled(const struct session *session);
void session_set_throttled(struct session *session, bool throttled);
bool session_has_tls(const struct session *session);
void session_set_has_tls(struct session *session, bool has_tls);
bool session_wirebuf_error(struct session *session);

/** Get peer address. */
struct sockaddr *session_get_peer(struct session *session);
/** Get pointer to server-side tls-related data. */
struct tls_ctx_t *session_tls_get_server_ctx(const struct session *session);
/** Set pointer to server-side tls-related data. */
void session_tls_set_server_ctx(struct session *session, struct tls_ctx_t *ctx);
/** Get pointer to client-side tls-related data. */
struct tls_client_ctx_t *session_tls_get_client_ctx(const struct session *session);
/** Set pointer to client-side tls-related data. */
void session_tls_set_client_ctx(struct session *session, struct tls_client_ctx_t *ctx);
/** Get pointer to that part of tls-related data which has common structure for 
 *  server and client. */
struct tls_common_ctx *session_tls_get_common_ctx(const struct session *session);

/** Get pointer to underlying libuv handle for IO operations. */
uv_handle_t *session_get_handle(struct session *session);
/** Set pointer to libuv handle for IO operations. */
int session_set_handle(struct session *session, uv_handle_t *handle);

/** Get pointer to session timer handle. */
uv_timer_t *session_get_timer(struct session *session);
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
/** Get length of data in the session wirebuffer. */
size_t session_wirebuf_get_len(struct session *session);
/** Get pointer to the beginning of free space in session wirebuffer. */
uint8_t *session_wirebuf_get_free_start(struct session *session);
/** Get amount of free space in session wirebuffer. */
size_t session_wirebuf_get_free_size(struct session *session);
/** Discard all data in session wirebuffer. */
void session_wirebuf_discard(struct session *session);
/** Move all data to the beginning of the buffer. */
void session_wirebuf_compress(struct session *session);
int session_wirebuf_process(struct session *session);
ssize_t session_wirebuf_consume(struct session *session,
				const uint8_t *data, ssize_t len);

/** poison session structure with ASAN. */
void session_poison(struct session *session);
/** unpoison session structure with ASAN. */
void session_unpoison(struct session *session);

knot_pkt_t *session_produce_packet(struct session *session, knot_mm_t *mm);
int session_discard_packet(struct session *session, const knot_pkt_t *pkt);

void session_kill_ioreq(struct session *session, struct qr_task *task);

