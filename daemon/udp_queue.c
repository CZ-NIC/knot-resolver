/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "daemon/session.h"
#include "daemon/worker.h"
#include "lib/utils.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>

/* LATER: it might be useful to have this configurable during runtime,
 * but the structures below would have to change a little (broken up). */
#define UDP_QUEUE_LEN 64

struct qr_task;
/** A queue of up to UDP_QUEUE_LEN messages, meant for the same socket. */
typedef struct {
	int len; /**< The number of messages in the queue: 0..UDP_QUEUE_LEN */
	struct mmsghdr msgvec[UDP_QUEUE_LEN]; /**< Parameter for sendmmsg() */
	struct {
		struct qr_task *task; /**< Links for completion callbacks. */
		struct iovec msg_iov[1]; /**< storage for .msgvec[i].msg_iov */
	} items[UDP_QUEUE_LEN];
} udp_queue_t;

static udp_queue_t * udp_queue_create()
{
	udp_queue_t *q = calloc(1, sizeof(*q));
	for (int i = 0; i < UDP_QUEUE_LEN; ++i) {
		struct msghdr *mhi = &q->msgvec[i].msg_hdr;
		/* These shall remain always the same. */
		mhi->msg_iov = q->items[i].msg_iov;
		mhi->msg_iovlen = 1;
		/* msg_name and msg_namelen will be per-call,
		 * and the rest is OK to remain zeroed all the time. */
	}
	return q;
}

/** Singleton map: fd -> udp_queue_t, as a simple array of pointers.
 * FIXME: either free at exit or ignore the leaks. */
static udp_queue_t **the_udp_queues = NULL;
static int the_udp_queues_len = 0;

/** The queue is assumed to exist and nonempty. */
static void udp_queue_send(int fd)
{
	udp_queue_t *const q = the_udp_queues[fd];
	int sent_len = sendmmsg(fd, q->msgvec, q->len, 0);
	/* ATM we don't really do anything about failures. */
	int err = sent_len < 0 ? errno : EAGAIN /* unknown error, really */;
	if (sent_len != q->len) { //FIXME: verbose only?
		kr_log_error("udp sendmmsg(): sent %d / %d, err %d", sent_len, q->len, err);
	}
	for (int i = 0; i < q->len; ++i) {
		qr_task_on_send(q->items[i].task, NULL, i < sent_len ? 0 : err);
	}
	q->len = 0;
}

void udp_queue_push(int fd, struct kr_request *req, struct qr_task *task)
{
	if (fd < 0 || fd >= 65536) {
		kr_log_error("ERROR: called udp_queue_push(fd = %d, ...)\n", fd);
		abort();
	}
	/* Get a valid correct queue. */
	if (fd >= the_udp_queues_len) {
		const int new_len = fd + 1;
		the_udp_queues = realloc(the_udp_queues,
					sizeof(the_udp_queues[0]) * new_len);
		if (!the_udp_queues) abort();
		memset(the_udp_queues + the_udp_queues_len, 0,
			sizeof(the_udp_queues[0]) * (new_len - the_udp_queues_len));
		the_udp_queues_len = new_len;
	}
	if (unlikely(the_udp_queues[fd] == NULL))
		the_udp_queues[fd] = udp_queue_create();
	udp_queue_t *const q = the_udp_queues[fd];

	/* Append to the queue */
	struct sockaddr *sa = (struct sockaddr *)/*const-cast*/req->qsource.addr;
	q->msgvec[q->len].msg_hdr.msg_name = sa;
	q->msgvec[q->len].msg_hdr.msg_namelen = kr_sockaddr_len(sa);
	q->items[q->len].task = task;
	q->items[q->len].msg_iov[0] = (struct iovec){
		.iov_base = req->answer->wire,
		.iov_len  = req->answer->size,
	};
	++(q->len);

	if (q->len >= UDP_QUEUE_LEN) {
		assert(q->len == UDP_QUEUE_LEN);
		udp_queue_send(fd);
	}
}

static void udp_queue_check(uv_idle_t *handle)
{
	static uint64_t last_stamp = 0;
	//uv_update_time(handle->loop);
	uint64_t now = uv_now(handle->loop);
	if (likely(now == last_stamp)) return;
	last_stamp = now;
	/* LATER(optim.): this probably isn't ideal, and we might better
	 * maintain a list of fd numbers that might be non-empty ATM -
	 * appended when a queue gets its first item and emptied just here. */
	for (int fd = 0; fd < the_udp_queues_len; ++fd) {
		udp_queue_t *const q = the_udp_queues[fd];
		if (unlikely(q && q->len))
			udp_queue_send(fd);
	}
}

int udp_queue_init_global(uv_loop_t *loop)
{
	static uv_idle_t handle;
	int ret = uv_idle_init(loop, &handle);
	if (!ret) ret = uv_idle_start(&handle, udp_queue_check);
	return ret;
}

