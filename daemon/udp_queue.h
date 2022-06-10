/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <uv.h>
#include "lib/weakptr.h"

struct kr_request;
typedef weakptr_t qr_task_weakptr_t;

/** Initialize the global state for udp_queue. */
int udp_queue_init_global(uv_loop_t *loop);

/** Send req->answer via UDP, possibly not immediately. */
void udp_queue_push(int fd, struct kr_request *req, qr_task_weakptr_t task);

