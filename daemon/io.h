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

#include <uv.h>
#include <libknot/packet/pkt.h>
#include <gnutls/gnutls.h>
#include "lib/generic/array.h"
#include "daemon/worker.h"

struct tls_ctx_t;
struct tls_client_ctx_t;

/* Per-session (TCP or UDP) persistent structure,
 * that exists between remote counterpart and a local socket.
 */
struct session {
	bool outgoing; /**< True: to upstream; false: from a client. */
	bool throttled;
	bool has_tls;
	bool connected;
	bool closing;
	bool proxy_enabled;
	union inaddr peer;
	uv_handle_t *handle;
	uv_timer_t timeout;
	struct qr_task *buffering; /**< Worker buffers the incomplete TCP query here. */
	struct tls_ctx_t *tls_ctx;
	struct tls_client_ctx_t *tls_client_ctx;

	uint8_t msg_hdr[4];  /**< Buffer for DNS message header. */
	ssize_t msg_hdr_idx; /**< The number of bytes in msg_hdr filled so far. */

	qr_tasklist_t tasks;
	qr_tasklist_t waiting;
	ssize_t bytes_to_skip;
};

void session_free(struct session *s);
struct session *session_new(void);

int udp_bind(uv_udp_t *handle, struct sockaddr *addr);
int udp_bindfd(uv_udp_t *handle, int fd);
int tcp_bind(uv_tcp_t *handle, struct sockaddr *addr, int tcp_backlog);
int tcp_bind_tls(uv_tcp_t *handle, struct sockaddr *addr, int tcp_backlog);
int tcp_bindfd(uv_tcp_t *handle, int fd, int tcp_backlog);
int tcp_bindfd_tls(uv_tcp_t *handle, int fd, int tcp_backlog);

/** Initialize the handle, incl. ->data = struct session * instance. type = SOCK_* */
int io_create(uv_loop_t *loop, uv_handle_t *handle, int type, unsigned family);
void io_deinit(uv_handle_t *handle);
void io_free(uv_handle_t *handle);

int io_start_read(uv_handle_t *handle);
int io_stop_read(uv_handle_t *handle);
