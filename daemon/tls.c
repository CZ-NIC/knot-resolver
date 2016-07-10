/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 * 
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gnutls/gnutls.h>
#include <stdlib.h>
#include <errno.h>
#include <uv.h>

#include "daemon/worker.h"
#include "daemon/tls.h"
#include "daemon/io.h"

static const char *priorities = "NORMAL";

/* gnutls_record_recv and gnutls_record_send */
struct tls_ctx_t {
	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_creds;
	int handshake_done;

	uv_stream_t *handle;

	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[4096];

	/* for writing to the network */
	uv_write_t *writer;
	uv_write_cb	write_cb;
};

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) fprintf(stderr, "[daem] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

static void
kres_gnutls_log(int level, const char *message)
{
	kr_log_error("[tls] gnutls: (%d) %s", level, message);
}


static		ssize_t
kres_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	const uv_buf_t ub = {(void *)buf, len};
	int	ret;

	DEBUG_MSG("[tls] push %zu <%p>\n", len, h);
	if (t == NULL) {
		errno = EFAULT;
		return -1;
	}
	ret = uv_try_write(t->handle, &ub, 1);

	if (ret > 0)
		return (ssize_t) ret;
	if (ret == UV_EAGAIN)
		errno = EAGAIN;
	else {
		kr_log_error("[tls] uv_try_write unknown error: %d\n", ret);
		errno = EIO;	/* dkg just picked this at random */
	}
	return -1;
}


static		ssize_t
kres_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	ssize_t	avail = t->nread - t->consumed;
	ssize_t	transfer;
	DEBUG_MSG("[tls] pull wanted: %zu available: %zu\n", len, avail);

	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		return -1;
	}
	if (avail <= len)
		transfer = avail;
	else
		transfer = len;

	memcpy(buf, t->buf + t->consumed, transfer);
	t->consumed += transfer;
	return transfer;
}

static		ssize_t
kres_gnutls_push_vec(gnutls_transport_ptr_t h, const giovec_t * iov, int iovcnt)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	int	ret;

	DEBUG_MSG("vecpush %d (%p) handle: <%p> writer <%p>\n", iovcnt, iov, t->handle, t->writer);

	/*
	 * because of the struct of giovec_t is identical to struct iovec;
	 * and uv_buf_t header (uv-unix.h) says it may be cast to struct
	 * iovec; so we should be able to just cast directly.
	 */
	ret = uv_write(t->writer, t->handle, (uv_buf_t *) iov, iovcnt, t->write_cb);
	if (ret >= 0) {
		/* Pending ioreq on current task */
		return (ssize_t) ret;
	}
	switch (ret) {
	case UV_EAGAIN:
		errno = EAGAIN;
		break;
	case UV_EINTR:
		errno = EINTR;
		break;
	default:
		kr_log_error("[tls] uv_write unknown error: %d\n", ret);
		errno = EIO;	/* dkg just picked this at random */
	}
	return -1;
}

struct tls_ctx_t *
tls_new(struct worker_ctx *worker)
{
	int	err;
	struct tls_ctx_t *t;
	struct network *net = &worker->engine->net;
	const char *errpos;

	if (!net->tls_cert) {
		kr_log_error("[tls] net.tls_cert is missing; no TLS\n");
	}
	if (!net->tls_key) {
		kr_log_error("[tls] net.tls_key is missing; no TLS\n");
	}
	if (!net->tls_key || !net->tls_cert) {
		return NULL;
	}
	t = calloc(1, sizeof(struct tls_ctx_t));

	if (t == NULL) {
		kr_log_error("[tls] failed to allocate TLS context\n");
		return NULL;
	}
	/* FIXME: this should only be done once on the daemon */
	/* FIXME: propagate verbosity here? */
	gnutls_global_set_log_function(kres_gnutls_log);
	gnutls_global_set_log_level(0);

	/*
	 * FIXME: credentials should be global, instead of per-session; but
	 * then we would have to keep track of which sessions use them before
	 * changing them dyamically
	 */
	if ((err = gnutls_certificate_allocate_credentials(&t->x509_creds))) {
		kr_log_error("[tls] gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		tls_free(t);
		return NULL;
	}
	err = gnutls_certificate_set_x509_system_trust(t->x509_creds);
	if (err < 0) {
		kr_log_error("[tls] warning: gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
	if ((err = gnutls_certificate_set_x509_key_file(t->x509_creds, net->tls_cert,
				      net->tls_key, GNUTLS_X509_FMT_PEM))) {
		kr_log_error("[tls] gnutls_certificate_set_x509_key_file(%s,%s) failed: %d (%s)\n",
		net->tls_cert, net->tls_key, err, gnutls_strerror_name(err));
		tls_free(t);
		return NULL;
	}
	if ((err = gnutls_init(&t->session, GNUTLS_SERVER | GNUTLS_NONBLOCK))) {
		kr_log_error("[tls] gnutls_init() failed: %d (%s)\n",
			     err, gnutls_strerror_name(err));
		tls_free(t);
		return NULL;
	}
	if ((err = gnutls_credentials_set(t->session, GNUTLS_CRD_CERTIFICATE,
					  t->x509_creds))) {
		kr_log_error("[tls] warning: gnutls_credentials_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
	if ((err = gnutls_priority_set_direct(t->session, priorities, &errpos))) {
		kr_log_error("[tls] warning: setting priority '%s' failed at character %zd (...'%s') with error (%d) %s\n",
			     priorities, errpos - priorities, errpos, err, gnutls_strerror_name(err));
	}
	gnutls_transport_set_pull_function(t->session, kres_gnutls_pull);
	/*
	 * gnutls_transport_set_vec_push_function (t->session,
	 * kres_gnutls_push_vec);
	 */
	gnutls_transport_set_push_function(t->session, kres_gnutls_push);
	gnutls_transport_set_ptr(t->session, t);

	return t;
}

void
tls_free(struct tls_ctx_t *tls)
{
	if (!tls) {
		return;
	}
	/* FIXME: do we want to do gnutls_bye() to close TLS cleanly ? */
	if (tls->session) {
		gnutls_deinit(tls->session);
		tls->session = NULL;
	}
	if (tls->x509_creds) {
		gnutls_certificate_free_credentials(tls->x509_creds);
		tls->x509_creds = NULL;
	}
	free(tls);
}

int
push_tls(struct qr_task *task, uv_handle_t * handle, knot_pkt_t * pkt,
	 uv_write_t * writer, qr_task_send_cb on_send)
{
	ssize_t count;
	if (!pkt) {
		kr_log_error("[tls] cannot push null packet\n");
		return on_send(task, handle, kr_error(EIO));
	}
	uint16_t pkt_size = htons(pkt->size);

	struct session *session = handle->data;
	if (!session) {
		kr_log_error("[tls] no session on push\n");
		return on_send(task, handle, kr_error(EIO));
	}
	struct tls_ctx_t *tls_p = session->tls_ctx;
	if (!tls_p) {
		kr_log_error("[tls] no tls context on push\n");
		/* FIXME: might be necessary if we ever do outbound TLS */
		return on_send(task, handle, kr_error(EIO));
	}
	tls_p->handle = (uv_stream_t *) handle;
	tls_p->writer = writer;
	gnutls_record_cork(tls_p->session);
	count = gnutls_record_send(tls_p->session, &pkt_size, sizeof(pkt_size));
	if (count != sizeof(pkt_size)) {
		kr_log_error("[tls] gnutls_record_send pkt_size fail wanted: %u (%zd) %s\n",
			     pkt_size, count, gnutls_strerror_name(count));
		return on_send(task, handle, kr_error(EIO));
	}
	count = gnutls_record_send(tls_p->session, pkt->wire, pkt->size);
	if (count != pkt->size) {
		kr_log_error("[tls] gnutls_record_send wire fail wanted: %zu (%zd) %s\n",
			     pkt->size, count, gnutls_strerror_name(count));
		return on_send(task, handle, kr_error(EIO));
	}
	count = gnutls_record_uncork(tls_p->session, 0);
	if (count != sizeof(pkt_size) + pkt->size) {
		if (count == GNUTLS_E_AGAIN || count == GNUTLS_E_INTERRUPTED) {
			kr_log_error("[tls] gnutls_record_send incomplete: %zu (%zd) %s\n",
			     pkt->size, count, gnutls_strerror_name(count));
			/*
			 * FIXME: we need to know when this frees up; when it
			 * does, we should do gnutls_record_send(tls.session,
			 * NULL, 0);   how do i know?
			 */
		} else {
			kr_log_error("[tls] gnutls_record_send wire fail wanted: %zu (%zd) %s\n",
			     pkt->size, count, gnutls_strerror_name(count));
		}
		return on_send(task, handle, kr_error(EIO));
	}
	return count;
}


int 
worker_process_tls(struct worker_ctx *worker, uv_stream_t * handle, const uint8_t * buf, ssize_t nread)
{
	struct session *session = handle->data;
	struct tls_ctx_t *tls_p = session->tls_ctx;
	if (!tls_p) {
		return kr_error(ENOSYS);
	}
	int	err;
	ssize_t count;

	tls_p->buf = buf;
	tls_p->nread = nread;
	tls_p->handle = handle;
	tls_p->consumed = 0;	/* FIXME: doesn't handle split TLS records */
	if (!tls_p->handshake_done) {
		kr_log_error("[tls] handshake not done, what is going on?\n");
		err = gnutls_handshake(tls_p->session);
		if (!err) {
			tls_p->handshake_done = 1;
		} else {
			kr_log_error("[tls] gnutls handshake gets: %d (%s)\n", err, gnutls_strerror_name(err));
			if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED) {
				return 0; /* Wait for more */
			}
			return kr_error(err);
		}
	}

	/* FIXME: Decoded buffer should be at least as big as received bytes, otherwise we may lose
	 *        records, especially with pipelined queries. Quick solution is to read multiple times.
	 *        instead of aggregating decoded data into output buffer and submit once, but it's slower.
	 */
	int pushed_queries = 0;
	while (true) {
		count = gnutls_record_recv(tls_p->session, tls_p->recv_buf, sizeof(tls_p->recv_buf));
		if (count == 0) {
			/* this means there has been an end of the stream */
			kr_log_error("[tls] got zero from gnutls_record_recv\n");
			worker_submit(worker, (uv_handle_t *) handle, NULL, NULL);
			return kr_error(EIO);
		}
		if (count < 0) {
			if (count == GNUTLS_E_AGAIN || count == GNUTLS_E_INTERRUPTED) {
				return pushed_queries; /* Wait for more */
			} else {
				kr_log_error("[tls] unknown gnutls_record_recv error: (%zd) %s\n",
					     count, gnutls_strerror_name(count));
				worker_submit(worker, (uv_handle_t *) handle, NULL, NULL);
				return kr_error(EIO);
			}
		}
		kr_log_error("[tls] we got %zd cleartext octets\n", count);
		int ret = worker_process_tcp(worker, handle, tls_p->recv_buf, count);
		if (ret < 0) {
			return ret;
		}
		pushed_queries += ret;
	}
	return pushed_queries;
}

#undef DEBUG_MSG
