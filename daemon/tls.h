/*  Copyright (C) 2016 American Civil Liberties Union (ACLU)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <uv.h>
#include <libknot/packet/pkt.h>

struct tls_ctx_t;

struct tls_ctx_t* tls_new(struct worker_ctx *worker);
void tls_free(struct tls_ctx_t* tls);

int push_tls(struct qr_task *task, uv_handle_t *handle, knot_pkt_t *pkt,
	     uv_write_t *writer, qr_task_send_cb on_send);

int worker_process_tls(struct worker_ctx *worker, uv_stream_t *handle, const uint8_t *buf, ssize_t nread);
