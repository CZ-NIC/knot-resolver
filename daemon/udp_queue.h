/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <uv.h>
struct kr_request;
struct qr_task;

typedef void (*udp_queue_cb)(int status, void *baton);

/** Initialize the global state for udp_queue. */
int udp_queue_init_global(uv_loop_t *loop);

/** Send req->answer via UDP, possibly not immediately. */
void udp_queue_push(int fd, const struct sockaddr *sa, char *buf, size_t buf_len,
                    udp_queue_cb cb, void *baton);

