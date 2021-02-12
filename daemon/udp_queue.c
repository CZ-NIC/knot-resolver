/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"
#include "daemon/udp_queue.h"

#include "daemon/session.h"
#include "daemon/worker.h"
#include "lib/generic/array.h"
#include "lib/utils.h"

struct qr_task;

#include <assert.h>
#include <sys/socket.h>


#if !ENABLE_SENDMMSG
int udp_queue_init_global(uv_loop_t *loop)
{
	return 0;
}
/* Appease the linker in case this unused call isn't optimized out. */
void udp_queue_push(int fd, struct kr_request *req, struct qr_task *task)
{
	abort();
}
#else

/* LATER: it might be useful to have this configurable during runtime,
 * but the structures below would have to change a little (broken up). */
#define UDP_QUEUE_LEN 64

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

/** Global state for udp_queue_*.  Note: we never free the pointed-to memory. */
struct {
	/** Singleton map: fd -> udp_queue_t, as a simple array of pointers. */
	udp_queue_t **udp_queues;
	int udp_queues_len;

	/** List of FD numbers that might have a non-empty queue. */
	array_t(int) waiting_fds;

	uv_check_t check_handle;
} static state = {0};

/** Empty the given queue.  The queue is assumed to exist (but may be empty). */
static void udp_queue_send(int fd)
{
	udp_queue_t *const q = state.udp_queues[fd];
	if (!q->len) return;
	// whole queue shares `fd`, so the UV handle is the same as well
	struct request_ctx *ctx = worker_task_get_request(q->items[0].task);
	const uv_handle_t * const uv_h =
		session_get_handle(worker_request_get_source_session(ctx));
	assert(uv_h);

	for (int i = 0; i < q->len;) { // send from `i` onwards
		int len_done = sendmmsg(fd, q->msgvec + i, q->len - i, 0);
		(void)likely(len_done == q->len - i);

		if (len_done < 0) { // the first failed already
			if (errno == EINTR) // standard syscall restart
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
				// Temporary overload.  ATM we don't add yet another
				// layer of buffering, so we give up on the whole batch.
				for (; i < q->len; ++i) {
					qr_task_on_send(q->items[i].task, uv_h,
							kr_error(ENOBUFS));
					worker_task_unref(q->items[i].task);
				}
				break;
			}
			// otherwise we fail this single packet and retry the rest
			qr_task_on_send(q->items[i].task, uv_h, kr_error(errno));
			worker_task_unref(q->items[i].task);
			++i;
		} else
		// These packets succeeded.  If any packet remains,
		// the error code was lost by OS, so we retry (keep `i` pointing to it).
		while (len_done > 0) {
			qr_task_on_send(q->items[i].task, uv_h, kr_ok());
			worker_task_unref(q->items[i].task);
			++i, --len_done;
		}
	}
	q->len = 0;
}

/** Periodical callback to send all queued packets. */
static void udp_queue_check(uv_check_t *handle)
{
	for (int i = 0; i < state.waiting_fds.len; ++i) {
		udp_queue_send(state.waiting_fds.at[i]);
	}
	state.waiting_fds.len = 0;
}

int udp_queue_init_global(uv_loop_t *loop)
{
	int ret = uv_check_init(loop, &state.check_handle);
	if (!ret) ret = uv_check_start(&state.check_handle, udp_queue_check);
	return ret;
}

void udp_queue_push(int fd, struct kr_request *req, struct qr_task *task)
{
	if (fd < 0) {
		kr_log_error("ERROR: called udp_queue_push(fd = %d, ...)\n", fd);
		abort();
	}
	worker_task_ref(task);
	/* Get a valid correct queue. */
	if (fd >= state.udp_queues_len) {
		const int new_len = fd + 1;
		state.udp_queues = realloc(state.udp_queues,
					sizeof(state.udp_queues[0]) * new_len);
		if (!state.udp_queues) abort();
		memset(state.udp_queues + state.udp_queues_len, 0,
			sizeof(state.udp_queues[0]) * (new_len - state.udp_queues_len));
		state.udp_queues_len = new_len;
	}
	if (unlikely(state.udp_queues[fd] == NULL))
		state.udp_queues[fd] = udp_queue_create();
	udp_queue_t *const q = state.udp_queues[fd];

	/* Append to the queue */
	struct sockaddr *sa = (struct sockaddr *)/*const-cast*/req->qsource.addr;
	q->msgvec[q->len].msg_hdr.msg_name = sa;
	q->msgvec[q->len].msg_hdr.msg_namelen = kr_sockaddr_len(sa);
	q->items[q->len].task = task;
	q->items[q->len].msg_iov[0] = (struct iovec){
		.iov_base = req->answer->wire,
		.iov_len  = req->answer->size,
	};
	if (q->len == 0)
		array_push(state.waiting_fds, fd);
	++(q->len);

	if (q->len >= UDP_QUEUE_LEN) {
		assert(q->len == UDP_QUEUE_LEN);
		udp_queue_send(fd);
		/* We don't need to search state.waiting_fds;
		 * anyway, it's more efficient to let the hook do that. */
	}
}

#endif

