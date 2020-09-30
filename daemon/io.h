/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <lua.h>
#include <uv.h>
#include <libknot/packet/pkt.h>
#include <gnutls/gnutls.h>
#include "lib/generic/array.h"
#include "daemon/worker.h"
#include "daemon/engine.h"

struct tls_ctx;
struct tls_client_ctx;

/** Bind address into a file-descriptor (only, no libuv).  type is e.g. SOCK_DGRAM */
int io_bind(const struct sockaddr *addr, int type, const endpoint_flags_t *flags);
/** Initialize a UDP handle and start listening. */
int io_listen_udp(uv_loop_t *loop, uv_udp_t *handle, int fd);
/** Initialize a TCP handle and start listening. */
int io_listen_tcp(uv_loop_t *loop, uv_tcp_t *handle, int fd, int tcp_backlog, bool has_tls);
/** Initialize a pipe handle and start listening. */
int io_listen_pipe(uv_loop_t *loop, uv_pipe_t *handle, int fd);

/** Control socket / TTY - related functions. */
void io_tty_process_input(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void io_tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf);
void io_tty_accept(uv_stream_t *master, int status);

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
