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
	bool handshake_done;

	uv_stream_t *handle;

	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[4096];
};

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) fprintf(stderr, "[daem] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

static ssize_t kres_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len)
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

	if (ret > 0) {
		return (ssize_t) ret;
	}
	if (ret == UV_EAGAIN) {
		errno = EAGAIN;
	} else {
		kr_log_error("[tls] uv_try_write unknown error: %d\n", ret);
		errno = EIO;	/* dkg just picked this at random */
	}
	return -1;
}


static ssize_t kres_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	ssize_t	avail = t->nread - t->consumed;
	ssize_t	transfer;
	DEBUG_MSG("[tls] pull wanted: %zu available: %zu\n", len, avail);

	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		return -1;
	}
	if (avail <= len) {
		transfer = avail;
	} else {
		transfer = len;
	}

	memcpy(buf, t->buf + t->consumed, transfer);
	t->consumed += transfer;
	return transfer;
}

struct tls_ctx_t *tls_new(struct worker_ctx *worker)
{
	struct network *net = &worker->engine->net;

	if (!worker->x509_credentials) {
		kr_log_error("[tls] x509 credentials are missing; no TLS\n");
		return NULL;
	}
	struct tls_ctx_t *tls = calloc(1, sizeof(struct tls_ctx_t));

	if (tls == NULL) {
		kr_log_error("[tls] failed to allocate TLS context\n");
		return NULL;
	}

	int err;
	if ((err = gnutls_init(&tls->session, GNUTLS_SERVER | GNUTLS_NONBLOCK)) < 0) {
		kr_log_error("[tls] gnutls_init() failed: %d (%s)\n",
			     err, gnutls_strerror_name(err));
		tls_free(tls);
		return NULL;
	}
	if ((err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE,
                                          *worker->x509_credentials)) < 0) {
		kr_log_error("[tls] gnutls_credentials_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		tls_free(tls);
		return NULL;
	}
	const char *errpos;
	if ((err = gnutls_priority_set_direct(tls->session, priorities, &errpos)) < 0) {
		kr_log_error("[tls] setting priority '%s' failed at character %zd (...'%s') with error (%d) %s\n",
			     priorities, errpos - priorities, errpos, err, gnutls_strerror_name(err));
		tls_free(tls);
		return NULL;
	}
	gnutls_transport_set_pull_function(tls->session, kres_gnutls_pull);
	gnutls_transport_set_push_function(tls->session, kres_gnutls_push);
	gnutls_transport_set_ptr(tls->session, tls);

	return tls;
}

void tls_free(struct tls_ctx_t *tls)
{
	if (!tls) {
		return;
	}

	if (tls->session) {
		gnutls_bye(tls->session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(tls->session);
		tls->session = NULL;
	}
	free(tls);
}

int tls_push(struct qr_task *task, uv_handle_t* handle, knot_pkt_t * pkt)
{
	if (!pkt || !handle || !handle->data) {
		return kr_error(EINVAL);
	}

	struct session *session = handle->data;
	uint16_t pkt_size = htons(pkt->size);
	struct tls_ctx_t *tls_p = session->tls_ctx;
	if (!tls_p) {
		kr_log_error("[tls] no tls context on push\n");
		return kr_error(ENOENT);
	}
	gnutls_record_cork(tls_p->session);
	ssize_t count;
	if ((count = gnutls_record_send(tls_p->session, &pkt_size, sizeof(pkt_size)) < 0) ||
	    (count = gnutls_record_send(tls_p->session, pkt->wire, pkt->size) < 0)) {
		kr_log_error("[tls] gnutls_record_send failed: %zu (%zd) %s\n",
			     sizeof(pkt_size) + pkt->size, count, gnutls_strerror_name(count));
		return kr_error(EIO);
	}
	
	/* GNUTLS_RECORD_WAIT blocks until the data is sent or a fatal error occurs */
	count = gnutls_record_uncork(tls_p->session, GNUTLS_RECORD_WAIT);
	if (count != sizeof(pkt_size) + pkt->size) {
		kr_log_error("[tls] gnutls_record_uncork failed: %zu (%zd) %s\n",
			     sizeof(pkt_size) + pkt->size, count, gnutls_strerror_name(count));
		return kr_error(EIO);
	}

	return kr_ok();
}

int tls_process(struct worker_ctx *worker, uv_stream_t * handle, const uint8_t * buf, ssize_t nread)
{
	struct session *session = handle->data;
	struct tls_ctx_t *tls_p = session->tls_ctx;
	if (!tls_p) {
		return kr_error(ENOSYS);
	}

	tls_p->buf = buf;
	tls_p->nread = nread;
	tls_p->handle = handle;
	tls_p->consumed = 0;	/* TODO: doesn't handle split TLS records */
	if (!tls_p->handshake_done) {
		int err = gnutls_handshake(tls_p->session);
		if (!err) {
			tls_p->handshake_done = true;
		} else {
			if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED) {
				return 0; /* Wait for more */
			}
			return kr_error(err);
		}
	}

	while (true) {
		ssize_t count = gnutls_record_recv(tls_p->session, tls_p->recv_buf, sizeof(tls_p->recv_buf));
		if (count == 0) {
			kr_log_error("[tls] gnutls_record_recv peer has closed the TLS connection\n");
			return kr_error(EIO);
		} else if (count < 0 && gnutls_error_is_fatal(count) == 0) {
			/* gnutls_record_recv error not fatal, try reading again */
			continue;
		} else if (count < 0) {
			kr_log_error("[tls] gnutls_record_recv failed: (%zd) %s\n",
				     count, gnutls_strerror_name(count));
			return kr_error(EIO);
		}
		/* Now let worker_process_tcp handle the end-of-stream */
		return worker_process_tcp(worker, handle, tls_p->recv_buf, count);
	}
}

static int str_replace(char **where_ptr, const char *with)
{
	char *copy = with ? strdup(with) : NULL;
	if (with && !copy) {
		return kr_error(ENOMEM);
	}

	free(*where_ptr);
	*where_ptr = copy;
	return kr_ok();
}

int tls_certificate_set(struct worker_ctx *worker, const char *tls_cert, const char *tls_key)
{
	int err;

	if (!worker) {
		return kr_error(EINVAL);
	}

	gnutls_certificate_credentials_t *x509_credentials = calloc(1, sizeof(x509_credentials));
	if (x509_credentials == NULL) {
		return kr_error(ENOMEM);
	}
	
	if ((err = gnutls_certificate_allocate_credentials(x509_credentials)) < 0) {
		kr_log_error("[tls] gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return kr_error(ENOMEM);
	}
	if ((err = gnutls_certificate_set_x509_system_trust(*x509_credentials)) < 0) {
		if (err != GNUTLS_E_UNIMPLEMENTED_FEATURE) {
			kr_log_error("[tls] warning: gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			gnutls_certificate_free_credentials(*x509_credentials);
			return err;
		}
	}
	
	if (((err = str_replace(&worker->tls_cert, tls_cert)) != 0) ||
	    ((err = str_replace(&worker->tls_key, tls_key)) != 0)) {
		return kr_error(ENOMEM);
	}
	
	if ((err = gnutls_certificate_set_x509_key_file(*x509_credentials, tls_cert,
							tls_key, GNUTLS_X509_FMT_PEM)) < 0) {
		kr_log_error("[tls] gnutls_certificate_set_x509_key_file(%s,%s) failed: %d (%s)\n",
			     tls_cert, tls_key, err, gnutls_strerror_name(err));
		return kr_error(EINVAL);
	}
	// Exchange the x509 credentials
	gnutls_certificate_credentials_t *old_credentials = worker->x509_credentials;

	// Start using the new x509_credentials
	worker->x509_credentials = x509_credentials;

	// Deallocate old x509 credentials
	if (old_credentials) {
		gnutls_certificate_free_credentials(*old_credentials);
		free(old_credentials);
	}

	return kr_ok();
}

#undef DEBUG_MSG
