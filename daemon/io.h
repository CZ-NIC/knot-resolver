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
#include "lib/generic/array.h"

struct qr_task;
struct tls_ctx_t;

/* Per-session (TCP or UDP) persistent structure,
 * that exists between remote counterpart and a local socket.
 */
struct session {
	bool outgoing;
	bool throttled;
	bool has_tls;
	uv_timer_t timeout;
	struct qr_task *buffering; /**< Worker buffers the incomplete TCP query here. */
	struct tls_ctx_t *tls_ctx;
	array_t(struct qr_task *) tasks;
};

void session_free(struct session *s);
struct session *session_new(void);

int udp_bind(uv_udp_t *handle, struct sockaddr *addr);
int udp_bindfd(uv_udp_t *handle, int fd);
int tcp_bind(uv_tcp_t *handle, struct sockaddr *addr);
int tcp_bind_tls(uv_tcp_t *handle, struct sockaddr *addr);
int tcp_bindfd(uv_tcp_t *handle, int fd);
int tcp_bindfd_tls(uv_tcp_t *handle, int fd);

/** Initialize the handle, incl. ->data = struct session * instance. type = SOCK_* */
void io_create(uv_loop_t *loop, uv_handle_t *handle, int type);
void io_deinit(uv_handle_t *handle);
void io_free(uv_handle_t *handle);

int io_start_read(uv_handle_t *handle);
int io_stop_read(uv_handle_t *handle);
