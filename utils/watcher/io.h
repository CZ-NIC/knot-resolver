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
#include "worker.h"

struct tls_ctx_t;
struct tls_client_ctx_t;

/** Bind address into a file-descriptor (only, no libuv).  type is e.g. SOCK_DGRAM */
int io_bind(const struct sockaddr *addr, int type, const endpoint_flags_t *flags);
/** Initialize a UDP handle and start listening. */
int io_listen_udp(uv_loop_t *loop, uv_udp_t *handle, int fd);
/** Initialize a TCP handle and start listening. */
int io_listen_tcp(uv_loop_t *loop, uv_tcp_t *handle, int fd, int tcp_backlog, bool has_tls);

void tcp_timeout_trigger(uv_timer_t *timer);

/** Initialize the handle, incl. ->data = struct session * instance.
 * \param type = SOCK_*
 * \param family = AF_*
 * \param has_tls has meanings only when type is SOCK_STREAM */
int io_create(uv_loop_t *loop, uv_handle_t *handle, int type,
	      unsigned family, bool has_tls);
void io_deinit(uv_handle_t *handle);
void io_free(uv_handle_t *handle);

int io_start_read(uv_handle_t *handle);
int io_stop_read(uv_handle_t *handle);
