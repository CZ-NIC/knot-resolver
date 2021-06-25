/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 *               2016-2018 CZ.NIC, z.s.p.o
 *
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 *                 Ondřej Surý <ondrej@sury.org>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <uv.h>

#include <errno.h>
#include <stdlib.h>

#include "contrib/ucw/lib.h"
#include "contrib/base64.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/worker.h"
#include "daemon/session.h"

#define EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE (60*60*24*7)
#define GNUTLS_PIN_MIN_VERSION  0x030400

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(...) kr_log_verbose("[tls] " __VA_ARGS__)
#else
#define DEBUG_MSG(...)
#endif

struct async_write_ctx {
	uv_write_t write_req;
	struct tls_common_ctx *t;
	char buf[];
};

static char const server_logstring[] = "tls";
static char const client_logstring[] = "tls_client";

static int client_verify_certificate(gnutls_session_t tls_session);

/**
 * Set mandatory security settings from
 * https://tools.ietf.org/html/draft-ietf-dprive-dtls-and-tls-profiles-11#section-9
 * Performance optimizations are not implemented at the moment.
 */
static int kres_gnutls_set_priority(gnutls_session_t session) {
	static const char * const priorities =
		"NORMAL:" /* GnuTLS defaults */
		"-VERS-TLS1.0:-VERS-TLS1.1:" /* TLS 1.2 and higher */
		 /* Some distros by default allow features that are considered
		  * too insecure nowadays, so let's disable them explicitly. */
		"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";
	const char *errpos = NULL;
	int err = gnutls_priority_set_direct(session, priorities, &errpos);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			     priorities, errpos - priorities, errpos, gnutls_strerror_name(err), err);
	}
	return err;
}

static ssize_t kres_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
	if (kr_fails_assert(t)) {
		errno = EFAULT;
		return -1;
	}

	ssize_t	avail = t->nread - t->consumed;
	DEBUG_MSG("[%s] pull wanted: %zu available: %zu\n",
		  t->client_side ? "tls_client" : "tls", len, avail);
	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		return -1;
	}

	ssize_t	transfer = MIN(avail, len);
	memcpy(buf, t->buf + t->consumed, transfer);
	t->consumed += transfer;
	return transfer;
}

static void on_write_complete(uv_write_t *req, int status)
{
	if (kr_fails_assert(req->data))
		return;
	struct async_write_ctx *async_ctx = (struct async_write_ctx *)req->data;
	struct tls_common_ctx *t = async_ctx->t;
	if (t->write_queue_size)
		t->write_queue_size -= 1;
	else
		kr_assert(false);
	free(req->data);
}

static bool stream_queue_is_empty(struct tls_common_ctx *t)
{
	return (t->write_queue_size == 0);
}

static ssize_t kres_gnutls_vec_push(gnutls_transport_ptr_t h, const giovec_t * iov, int iovcnt)
{
	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
	if (kr_fails_assert(t)) {
		errno = EFAULT;
		return -1;
	}

	if (iovcnt == 0) {
		return 0;
	}

	if (kr_fails_assert(t->session)) {
		errno = EFAULT;
		return -1;
	}
	uv_stream_t *handle = (uv_stream_t *)session_get_handle(t->session);
	if (kr_fails_assert(handle && handle->type == UV_TCP)) {
		errno = EFAULT;
		return -1;
	}

	/*
	 * This is a little bit complicated. There are two different writes:
	 * 1. Immediate, these don't need to own the buffered data and return immediately
	 * 2. Asynchronous, these need to own the buffers until the write completes
	 * In order to avoid copying the buffer, an immediate write is tried first if possible.
	 * If it isn't possible to write the data without queueing, an asynchronous write
	 * is created (with copied buffered data).
	 */

	size_t total_len = 0;
	uv_buf_t uv_buf[iovcnt];
	for (int i = 0; i < iovcnt; ++i) {
		uv_buf[i].base = iov[i].iov_base;
		uv_buf[i].len = iov[i].iov_len;
		total_len += iov[i].iov_len;
	}

	/* Try to perform the immediate write first to avoid copy */
	int ret = 0;
	if (stream_queue_is_empty(t)) {
		ret = uv_try_write(handle, uv_buf, iovcnt);
		DEBUG_MSG("[%s] push %zu <%p> = %d\n",
		    t->client_side ? "tls_client" : "tls", total_len, h, ret);
		/* from libuv documentation -
		   uv_try_write will return either:
		     > 0: number of bytes written (can be less than the supplied buffer size).
		     < 0: negative error code (UV_EAGAIN is returned if no data can be sent immediately).
		*/
		if (ret == total_len) {
			/* All the data were buffered by libuv.
			 * Return. */
			return ret;
		}

		if (ret < 0 && ret != UV_EAGAIN) {
			/* uv_try_write() has returned error code other then UV_EAGAIN.
			 * Return. */
			kr_log_verbose("[%s] uv_try_write error: %s\n",
				       t->client_side ? "tls_client" : "tls", uv_strerror(ret));
			ret = -1;
			errno = EIO;
			return ret;
		}
		/* Since we are here expression below is true
		 * (ret != total_len) && (ret >= 0 || ret == UV_EAGAIN)
		 * or the same
		 * (ret != total_len && ret >= 0) || (ret != total_len && ret == UV_EAGAIN)
		 * i.e. either occurs partial write or UV_EAGAIN.
		 * Proceed and copy data amount to owned memory and perform async write.
		 */
		if (ret == UV_EAGAIN) {
			/* No data were buffered, so we must buffer all the data. */
			ret = 0;
		}
	}

	/* Fallback when the queue is full, and it's not possible to do an immediate write */
	char *p = malloc(sizeof(struct async_write_ctx) + total_len - ret);
	if (p != NULL) {
		struct async_write_ctx *async_ctx = (struct async_write_ctx *)p;
		/* Save pointer to session tls context */
		async_ctx->t = t;
		char *buf = async_ctx->buf;
		/* Skip data written in the partial write */
		size_t to_skip = ret;
		/* Copy the buffer into owned memory */
		size_t off = 0;
		for (int i = 0; i < iovcnt; ++i) {
			if (to_skip > 0) {
				/* Ignore current buffer if it's all skipped */
				if (to_skip >= uv_buf[i].len) {
					to_skip -= uv_buf[i].len;
					continue;
				}
				/* Skip only part of the buffer */
				uv_buf[i].base += to_skip;
				uv_buf[i].len -= to_skip;
				to_skip = 0;
			}
			memcpy(buf + off, uv_buf[i].base, uv_buf[i].len);
			off += uv_buf[i].len;
		}
		uv_buf[0].base = buf;
		uv_buf[0].len = off;

		/* Create an asynchronous write request */
		uv_write_t *write_req = &async_ctx->write_req;
		memset(write_req, 0, sizeof(uv_write_t));
		write_req->data = p;

		/* Perform an asynchronous write with a callback */
		if (uv_write(write_req, handle, uv_buf, 1, on_write_complete) == 0) {
			ret = total_len;
			t->write_queue_size += 1;
		} else {
			free(p);
			kr_log_verbose("[%s] uv_write error: %s\n",
				       t->client_side ? "tls_client" : "tls", uv_strerror(ret));
			errno = EIO;
			ret = -1;
		}
	} else {
		errno = ENOMEM;
		ret = -1;
	}

	DEBUG_MSG("[%s] queued %zu <%p> = %d\n",
	    t->client_side ? "tls_client" : "tls", total_len, h, ret);

	return ret;
}

/** Perform TLS handshake and handle error codes according to the documentation.
  * See See https://gnutls.org/manual/html_node/TLS-handshake.html#TLS-handshake
  * The function returns kr_ok() or success or non fatal error, kr_error(EAGAIN) on blocking, or kr_error(EIO) on fatal error.
  */
static int tls_handshake(struct tls_common_ctx *ctx, tls_handshake_cb handshake_cb) {
	struct session *session = ctx->session;
	const char *logstring = ctx->client_side ? client_logstring : server_logstring;

	int err = gnutls_handshake(ctx->tls_session);
	if (err == GNUTLS_E_SUCCESS) {
		/* Handshake finished, return success */
		ctx->handshake_state = TLS_HS_DONE;
		struct sockaddr *peer = session_get_peer(session);
		kr_log_verbose("[%s] TLS handshake with %s has completed\n",
			       logstring,  kr_straddr(peer));
		if (handshake_cb) {
			if (handshake_cb(session, 0) != kr_ok()) {
				return kr_error(EIO);
			}
		}
	} else if (err == GNUTLS_E_AGAIN) {
		return kr_error(EAGAIN);
	} else if (gnutls_error_is_fatal(err)) {
		/* Fatal errors, return error as it's not recoverable */
		kr_log_verbose("[%s] gnutls_handshake failed: %s (%d)\n",
			     logstring,
		             gnutls_strerror_name(err), err);
		/* Notify the peer about handshake failure via an alert. */
		gnutls_alert_send_appropriate(ctx->tls_session, err);
		if (handshake_cb) {
			handshake_cb(session, -1);
		}
		return kr_error(EIO);
	} else if (err == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		/* Handle warning when in verbose mode */
		const char *alert_name = gnutls_alert_get_name(gnutls_alert_get(ctx->tls_session));
		if (alert_name != NULL) {
			struct sockaddr *peer = session_get_peer(session);
			kr_log_verbose("[%s] TLS alert from %s received: %s\n",
				       logstring, kr_straddr(peer), alert_name);
		}
	}
	return kr_ok();
}


struct tls_ctx *tls_new(struct worker_ctx *worker)
{
	if (kr_fails_assert(worker && worker->engine))
		return NULL;

	struct network *net = &worker->engine->net;
	if (!net->tls_credentials) {
		net->tls_credentials = tls_get_ephemeral_credentials(worker->engine);
		if (!net->tls_credentials) {
			kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
			return NULL;
		}
		kr_log_info(TLS, "Using ephemeral TLS credentials\n");
		tls_credentials_log_pins(net->tls_credentials);
	}

	time_t now = time(NULL);
	if (net->tls_credentials->valid_until != GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION) {
		if (net->tls_credentials->ephemeral_servicename) {
			/* ephemeral cert: refresh if due to expire within a week */
			if (now >= net->tls_credentials->valid_until - EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE) {
				struct tls_credentials *newcreds = tls_get_ephemeral_credentials(worker->engine);
				if (newcreds) {
					tls_credentials_release(net->tls_credentials);
					net->tls_credentials = newcreds;
					kr_log_info(TLS, "Renewed expiring ephemeral X.509 cert\n");
				} else {
					kr_log_error(TLS, "Failed to renew expiring ephemeral X.509 cert, using existing one\n");
				}
			}
		} else {
			/* non-ephemeral cert: warn once when certificate expires */
			if (now >= net->tls_credentials->valid_until) {
				kr_log_error(TLS, "X.509 certificate has expired!\n");
				net->tls_credentials->valid_until = GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
			}
		}
	}

	struct tls_ctx *tls = calloc(1, sizeof(struct tls_ctx));
	if (tls == NULL) {
		kr_log_error(TLS, "failed to allocate TLS context\n");
		return NULL;
	}

	int err = gnutls_init(&tls->c.tls_session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_init(): %s (%d)\n", gnutls_strerror_name(err), err);
		tls_free(tls);
		return NULL;
	}
	tls->credentials = tls_credentials_reserve(net->tls_credentials);
	err = gnutls_credentials_set(tls->c.tls_session, GNUTLS_CRD_CERTIFICATE,
				     tls->credentials->credentials);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_credentials_set(): %s (%d)\n", gnutls_strerror_name(err), err);
		tls_free(tls);
		return NULL;
	}
	if (kres_gnutls_set_priority(tls->c.tls_session) != GNUTLS_E_SUCCESS) {
		tls_free(tls);
		return NULL;
	}

	tls->c.worker = worker;
	tls->c.client_side = false;

	gnutls_transport_set_pull_function(tls->c.tls_session, kres_gnutls_pull);
	gnutls_transport_set_vec_push_function(tls->c.tls_session, kres_gnutls_vec_push);
	gnutls_transport_set_ptr(tls->c.tls_session, tls);

	if (net->tls_session_ticket_ctx) {
		tls_session_ticket_enable(net->tls_session_ticket_ctx,
					  tls->c.tls_session);
	}

	return tls;
}

void tls_close(struct tls_common_ctx *ctx)
{
	if (ctx == NULL || ctx->tls_session == NULL || kr_fails_assert(ctx->session))
		return;

	if (ctx->handshake_state == TLS_HS_DONE) {
		const struct sockaddr *peer = session_get_peer(ctx->session);
		kr_log_verbose("[%s] closing tls connection to `%s`\n",
			       ctx->client_side ? "tls_client" : "tls",
			       kr_straddr(peer));
		ctx->handshake_state = TLS_HS_CLOSING;
		gnutls_bye(ctx->tls_session, GNUTLS_SHUT_RDWR);
	}
}

void tls_free(struct tls_ctx *tls)
{
	if (!tls) {
		return;
	}

	if (tls->c.tls_session) {
		/* Don't terminate TLS connection, just tear it down */
		gnutls_deinit(tls->c.tls_session);
		tls->c.tls_session = NULL;
	}

	tls_credentials_release(tls->credentials);
	free(tls);
}

int tls_write(uv_write_t *req, uv_handle_t *handle, knot_pkt_t *pkt, uv_write_cb cb)
{
	if (!pkt || !handle || !handle->data) {
		return kr_error(EINVAL);
	}

	struct session *s = handle->data;
	struct tls_common_ctx *tls_ctx = session_tls_get_common_ctx(s);

	if (kr_fails_assert(tls_ctx && session_flags(s)->outgoing == tls_ctx->client_side))
		return kr_error(EINVAL);

	const uint16_t pkt_size = htons(pkt->size);
	const char *logstring = tls_ctx->client_side ? client_logstring : server_logstring;
	gnutls_session_t tls_session = tls_ctx->tls_session;

	gnutls_record_cork(tls_session);
	ssize_t count = 0;
	if ((count = gnutls_record_send(tls_session, &pkt_size, sizeof(pkt_size)) < 0) ||
	    (count = gnutls_record_send(tls_session, pkt->wire, pkt->size) < 0)) {
		kr_log_verbose("[%s] gnutls_record_send failed: %s (%zd)\n",
			       logstring, gnutls_strerror_name(count), count);
		return kr_error(EIO);
	}

	const ssize_t submitted = sizeof(pkt_size) + pkt->size;

	int ret = gnutls_record_uncork(tls_session, GNUTLS_RECORD_WAIT);
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret)) {
			return kr_error(EAGAIN);
		} else {
			kr_log_verbose("[%s] gnutls_record_uncork failed: %s (%d)\n",
				       logstring, gnutls_strerror_name(ret), ret);
			return kr_error(EIO);
		}
	}

	if (ret != submitted) {
		kr_log_error(TLS, "[%s] gnutls_record_uncork didn't send all data (%d of %zd)\n",
		             logstring, ret, submitted);
		return kr_error(EIO);
	}

	/* The data is now accepted in gnutls internal buffers, the message can be treated as sent */
	req->handle = (uv_stream_t *)handle;
	cb(req, 0);

	return kr_ok();
}

ssize_t tls_process_input_data(struct session *s, const uint8_t *buf, ssize_t nread)
{
	struct tls_common_ctx *tls_p = session_tls_get_common_ctx(s);
	if (!tls_p) {
		return kr_error(ENOSYS);
	}

	if (kr_fails_assert(tls_p->session == s))
		return kr_error(EINVAL);
	const bool ok = tls_p->recv_buf == buf && nread <= sizeof(tls_p->recv_buf);
	if (kr_fails_assert(ok)) /* don't risk overflowing the buffer if we have a mistake somewhere */
		return kr_error(EINVAL);

	const char *logstring = tls_p->client_side ? client_logstring : server_logstring;

	tls_p->buf = buf;
	tls_p->nread = nread >= 0 ? nread : 0;
	tls_p->consumed = 0;

	/* Ensure TLS handshake is performed before receiving data.
	 * See https://www.gnutls.org/manual/html_node/TLS-handshake.html */
	while (tls_p->handshake_state <= TLS_HS_IN_PROGRESS) {
		int err = tls_handshake(tls_p, tls_p->handshake_cb);
		if (err == kr_error(EAGAIN)) {
			return 0; /* Wait for more data */
		} else if (err != kr_ok()) {
			return err;
		}
	}

	/* See https://gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination */
	ssize_t submitted = 0;
	uint8_t *wire_buf = session_wirebuf_get_free_start(s);
	size_t wire_buf_size = session_wirebuf_get_free_size(s);
	while (true) {
		ssize_t count = gnutls_record_recv(tls_p->tls_session, wire_buf, wire_buf_size);
		if (count == GNUTLS_E_AGAIN) {
			if (tls_p->consumed == tls_p->nread) {
				/* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
				break; /* No more data available in this libuv buffer */
			}
			continue;
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue;
		} else if (count == GNUTLS_E_REHANDSHAKE) {
			/* See https://www.gnutls.org/manual/html_node/Re_002dauthentication.html */
			struct sockaddr *peer = session_get_peer(s);
			kr_log_verbose("[%s] TLS rehandshake with %s has started\n",
				       logstring,  kr_straddr(peer));
			tls_set_hs_state(tls_p, TLS_HS_IN_PROGRESS);
			int err = kr_ok();
			while (tls_p->handshake_state <= TLS_HS_IN_PROGRESS) {
				err = tls_handshake(tls_p, tls_p->handshake_cb);
				if (err == kr_error(EAGAIN)) {
					break;
				} else if (err != kr_ok()) {
					return err;
				}
			}
			if (err == kr_error(EAGAIN)) {
				/* pull function is out of data */
				break;
			}
			/* There are can be data available, check it. */
			continue;
		} else if (count < 0) {
			kr_log_verbose("[%s] gnutls_record_recv failed: %s (%zd)\n",
				     logstring, gnutls_strerror_name(count), count);
			return kr_error(EIO);
		} else if (count == 0) {
			break;
		}
		DEBUG_MSG("[%s] received %zd data\n", logstring, count);
		wire_buf += count;
		wire_buf_size -= count;
		submitted += count;
		if (wire_buf_size == 0 && tls_p->consumed != tls_p->nread) {
			/* session buffer is full
			 * whereas not all the data were consumed */
			return kr_error(ENOSPC);
		}
	}
	/* Here all data must be consumed. */
	if (tls_p->consumed != tls_p->nread) {
		/* Something went wrong, better return error.
		 * This is most probably due to gnutls_record_recv() did not
		 * consume all available network data by calling kres_gnutls_pull().
		 * TODO assess the need for buffering of data amount.
		 */
		return kr_error(ENOSPC);
	}
	return submitted;
}

#if TLS_CAN_USE_PINS
/*
  DNS-over-TLS Out of band key-pinned authentication profile uses the
  same form of pins as HPKP:

  e.g.  pin-sha256="FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVI="

  DNS-over-TLS OOB key-pins: https://tools.ietf.org/html/rfc7858#appendix-A
  HPKP pin reference:        https://tools.ietf.org/html/rfc7469#appendix-A
*/
#define PINLEN  ((((32) * 8 + 4)/6) + 3 + 1)

/* Compute pin_sha256 for the certificate.
 * It may be in raw format - just TLS_SHA256_RAW_LEN bytes without termination,
 * or it may be a base64 0-terminated string requiring up to
 * TLS_SHA256_BASE64_BUFLEN bytes.
 * \return error code */
static int get_oob_key_pin(gnutls_x509_crt_t crt, char *outchar, ssize_t outchar_len, bool raw)
{
	if (kr_fails_assert(!raw || outchar_len >= TLS_SHA256_RAW_LEN)) {
		return kr_error(ENOSPC);
		/* With !raw we have check inside kr_base64_encode. */
	}
	gnutls_pubkey_t key;
	int err = gnutls_pubkey_init(&key);
	if (err != GNUTLS_E_SUCCESS) return err;

	gnutls_datum_t datum = { .data = NULL, .size = 0 };
	err = gnutls_pubkey_import_x509(key, crt, 0);
	if (err != GNUTLS_E_SUCCESS) goto leave;

	err = gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &datum);
	if (err != GNUTLS_E_SUCCESS) goto leave;

	char raw_pin[TLS_SHA256_RAW_LEN]; /* TMP buffer if raw == false */
	err = gnutls_hash_fast(GNUTLS_DIG_SHA256, datum.data, datum.size,
				(raw ? outchar : raw_pin));
	if (err != GNUTLS_E_SUCCESS || raw/*success*/)
		goto leave;
	/* Convert to non-raw. */
	err = kr_base64_encode((uint8_t *)raw_pin, sizeof(raw_pin),
			    (uint8_t *)outchar, outchar_len);
	if (err >= 0 && err < outchar_len) {
		err = GNUTLS_E_SUCCESS;
		outchar[err] = '\0'; /* kr_base64_encode() doesn't do it */
	} else if (kr_fails_assert(err < 0)) {
		err = kr_error(ENOSPC); /* base64 fits but '\0' doesn't */
		outchar[outchar_len - 1] = '\0';
	}
leave:
	gnutls_free(datum.data);
	gnutls_pubkey_deinit(key);
	return err;
}

void tls_credentials_log_pins(struct tls_credentials *tls_credentials)
{
	for (int index = 0;; index++) {
		gnutls_x509_crt_t *certs = NULL;
		unsigned int cert_count = 0;
		int err = gnutls_certificate_get_x509_crt(tls_credentials->credentials,
							index, &certs, &cert_count);
		if (err != GNUTLS_E_SUCCESS) {
			if (err != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
				kr_log_error(TLS, "could not get X.509 certificates (%d) %s\n",
						err, gnutls_strerror_name(err));
			}
			return;
		}

		for (int i = 0; i < cert_count; i++) {
			char pin[TLS_SHA256_BASE64_BUFLEN] = { 0 };
			err = get_oob_key_pin(certs[i], pin, sizeof(pin), false);
			if (err != GNUTLS_E_SUCCESS) {
				kr_log_error(TLS, "could not calculate RFC 7858 OOB key-pin from cert %d (%d) %s\n",
						i, err, gnutls_strerror_name(err));
			} else {
				kr_log_info(TLS, "RFC 7858 OOB key-pin (%d): pin-sha256=\"%s\"\n",
						i, pin);
			}
			gnutls_x509_crt_deinit(certs[i]);
		}
		gnutls_free(certs);
	}
}
#else
void tls_credentials_log_pins(struct tls_credentials *tls_credentials)
{
	kr_log_verbose("[tls] could not calculate RFC 7858 OOB key-pin; GnuTLS 3.4.0+ required\n");
}
#endif

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

static time_t _get_end_entity_expiration(gnutls_certificate_credentials_t creds)
{
	gnutls_datum_t data;
	gnutls_x509_crt_t cert = NULL;
	int err;
	time_t ret = GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;

	if ((err = gnutls_certificate_get_crt_raw(creds, 0, 0, &data)) != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "failed to get cert to check expiration: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_init(&cert)) != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "failed to initialize cert: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "failed to construct cert while checking expiration: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}

	ret = gnutls_x509_crt_get_expiration_time (cert);
 done:
	/* do not free data; g_c_get_crt_raw() says to treat it as
	 * constant. */
	gnutls_x509_crt_deinit(cert);
	return ret;
}

int tls_certificate_set(struct network *net, const char *tls_cert, const char *tls_key)
{
	if (!net) {
		return kr_error(EINVAL);
	}

	struct tls_credentials *tls_credentials = calloc(1, sizeof(*tls_credentials));
	if (tls_credentials == NULL) {
		return kr_error(ENOMEM);
	}

	int err = 0;
	if ((err = gnutls_certificate_allocate_credentials(&tls_credentials->credentials)) != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}
	if ((err = gnutls_certificate_set_x509_system_trust(tls_credentials->credentials)) < 0) {
		if (err != GNUTLS_E_UNIMPLEMENTED_FEATURE) {
			kr_log_warning(TLS, "warning: gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			tls_credentials_free(tls_credentials);
			return err;
		}
	}

	if ((str_replace(&tls_credentials->tls_cert, tls_cert) != 0) ||
	    (str_replace(&tls_credentials->tls_key, tls_key) != 0)) {
		tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}

	if ((err = gnutls_certificate_set_x509_key_file(tls_credentials->credentials,
							tls_cert, tls_key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
		tls_credentials_free(tls_credentials);
		kr_log_error(TLS, "gnutls_certificate_set_x509_key_file(%s,%s) failed: %d (%s)\n",
			     tls_cert, tls_key, err, gnutls_strerror_name(err));
		return kr_error(EINVAL);
	}
	/* record the expiration date: */
	tls_credentials->valid_until = _get_end_entity_expiration(tls_credentials->credentials);

	/* Exchange the x509 credentials */
	struct tls_credentials *old_credentials = net->tls_credentials;

	/* Start using the new x509_credentials */
	net->tls_credentials = tls_credentials;
	tls_credentials_log_pins(net->tls_credentials);

	if (old_credentials) {
		err = tls_credentials_release(old_credentials);
		if (err != kr_error(EBUSY)) {
			return err;
		}
	}

	return kr_ok();
}

struct tls_credentials *tls_credentials_reserve(struct tls_credentials *tls_credentials) {
	if (!tls_credentials) {
		return NULL;
	}
	tls_credentials->count++;
	return tls_credentials;
}

int tls_credentials_release(struct tls_credentials *tls_credentials) {
	if (!tls_credentials) {
		return kr_error(EINVAL);
	}
	if (--tls_credentials->count < 0) {
		tls_credentials_free(tls_credentials);
	} else {
		return kr_error(EBUSY);
	}
	return kr_ok();
}

void tls_credentials_free(struct tls_credentials *tls_credentials) {
	if (!tls_credentials) {
		return;
	}

	if (tls_credentials->credentials) {
		gnutls_certificate_free_credentials(tls_credentials->credentials);
	}
	if (tls_credentials->tls_cert) {
		free(tls_credentials->tls_cert);
	}
	if (tls_credentials->tls_key) {
		free(tls_credentials->tls_key);
	}
	if (tls_credentials->ephemeral_servicename) {
		free(tls_credentials->ephemeral_servicename);
	}
	free(tls_credentials);
}

void tls_client_param_unref(tls_client_param_t *entry)
{
	if (!entry || kr_fails_assert(entry->refs)) return;
	--(entry->refs);
	if (entry->refs) return;

	DEBUG_MSG("freeing TLS parameters %p\n", (void *)entry);

	for (int i = 0; i < entry->ca_files.len; ++i) {
		free_const(entry->ca_files.at[i]);
	}
	array_clear(entry->ca_files);

	free_const(entry->hostname);

	for (int i = 0; i < entry->pins.len; ++i) {
		free_const(entry->pins.at[i]);
	}
	array_clear(entry->pins);

	if (entry->credentials) {
		gnutls_certificate_free_credentials(entry->credentials);
	}

	if (entry->session_data.data) {
		gnutls_free(entry->session_data.data);
	}

	free(entry);
}
static int param_free(void **param, void *null)
{
	if (kr_fails_assert(param && *param))
		return -1;
	tls_client_param_unref(*param);
	return 0;
}
void tls_client_params_free(tls_client_params_t *params)
{
	if (!params) return;
	trie_apply(params, param_free, NULL);
	trie_free(params);
}

tls_client_param_t * tls_client_param_new()
{
	tls_client_param_t *e = calloc(1, sizeof(*e));
	if (kr_fails_assert(e))
		return NULL;
	/* Note: those array_t don't need further initialization. */
	e->refs = 1;
	int ret = gnutls_certificate_allocate_credentials(&e->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLSCLIENT, "error: gnutls_certificate_allocate_credentials() fails (%s)\n",
			     gnutls_strerror_name(ret));
		free(e);
		return NULL;
	}
	gnutls_certificate_set_verify_function(e->credentials, client_verify_certificate);
	return e;
}

/**
 * Convert an IP address and port number to binary key.
 *
 * \precond buffer \param key must have sufficient size
 * \param addr[in]
 * \param len[out] output length
 * \param key[out] output buffer
 */
static bool construct_key(const union inaddr *addr, uint32_t *len, char *key)
{
	switch (addr->ip.sa_family) {
	case AF_INET:
		memcpy(key, &addr->ip4.sin_port, sizeof(addr->ip4.sin_port));
		memcpy(key + sizeof(addr->ip4.sin_port), &addr->ip4.sin_addr,
			sizeof(addr->ip4.sin_addr));
		*len = sizeof(addr->ip4.sin_port) + sizeof(addr->ip4.sin_addr);
		return true;
	case AF_INET6:
		memcpy(key, &addr->ip6.sin6_port, sizeof(addr->ip6.sin6_port));
		memcpy(key + sizeof(addr->ip6.sin6_port), &addr->ip6.sin6_addr,
			sizeof(addr->ip6.sin6_addr));
		*len = sizeof(addr->ip6.sin6_port) + sizeof(addr->ip6.sin6_addr);
		return true;
	default:
		kr_assert(!EINVAL);
		return false;
	}
}
tls_client_param_t ** tls_client_param_getptr(tls_client_params_t **params,
				const struct sockaddr *addr, bool do_insert)
{
	if (kr_fails_assert(params && addr))
		return NULL;
	/* We accept NULL for empty map; ensure the map exists if needed. */
	if (!*params) {
		if (!do_insert) return NULL;
		*params = trie_create(NULL);
		if (kr_fails_assert(*params))
			return NULL;
	}
	/* Construct the key. */
	const union inaddr *ia = (const union inaddr *)addr;
	char key[sizeof(ia->ip6.sin6_port) + sizeof(ia->ip6.sin6_addr)];
	uint32_t len;
	if (!construct_key(ia, &len, key))
		return NULL;
	/* Get the entry. */
	return (tls_client_param_t **)
		(do_insert ? trie_get_ins : trie_get_try)(*params, key, len);
}

int tls_client_param_remove(tls_client_params_t *params, const struct sockaddr *addr)
{
	const union inaddr *ia = (const union inaddr *)addr;
	char key[sizeof(ia->ip6.sin6_port) + sizeof(ia->ip6.sin6_addr)];
	uint32_t len;
	if (!construct_key(ia, &len, key))
		return kr_error(EINVAL);
	trie_val_t param_ptr;
	int ret = trie_del(params, key, len, &param_ptr);
	if (ret)
		return kr_error(ret);
	tls_client_param_unref(param_ptr);
	return kr_ok();
}

/**
 * Verify that at least one certificate in the certificate chain matches
 * at least one certificate pin in the non-empty params->pins array.
 * \returns GNUTLS_E_SUCCESS if pin matches, any other value is an error
 */
static int client_verify_pin(const unsigned int cert_list_size,
				const gnutls_datum_t *cert_list,
				tls_client_param_t *params)
{
	if (kr_fails_assert(params->pins.len > 0))
		return GNUTLS_E_CERTIFICATE_ERROR;
#if TLS_CAN_USE_PINS
	for (int i = 0; i < cert_list_size; i++) {
		gnutls_x509_crt_t cert;
		int ret = gnutls_x509_crt_init(&cert);
		if (ret != GNUTLS_E_SUCCESS) {
			return ret;
		}

		ret = gnutls_x509_crt_import(cert, &cert_list[i], GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_deinit(cert);
			return ret;
		}

	#ifdef DEBUG
		if (VERBOSE_STATUS) {
			char pin_base64[TLS_SHA256_BASE64_BUFLEN];
			/* DEBUG: additionally compute and print the base64 pin.
			 * Not very efficient, but that's OK for DEBUG. */
			ret = get_oob_key_pin(cert, pin_base64, sizeof(pin_base64), false);
			if (ret == GNUTLS_E_SUCCESS) {
				DEBUG_MSG("[tls_client] received pin: %s\n", pin_base64);
			} else {
				DEBUG_MSG("[tls_client] failed to convert received pin\n");
				/* Now we hope that `ret` below can't differ. */
			}
		}
	#endif
		char cert_pin[TLS_SHA256_RAW_LEN];
		/* Get raw pin and compare. */
		ret = get_oob_key_pin(cert, cert_pin, sizeof(cert_pin), true);
		gnutls_x509_crt_deinit(cert);
		if (ret != GNUTLS_E_SUCCESS) {
			return ret;
		}
		for (size_t j = 0; j < params->pins.len; ++j) {
			const uint8_t *pin = params->pins.at[j];
			if (memcmp(cert_pin, pin, TLS_SHA256_RAW_LEN) != 0)
				continue; /* mismatch */
			DEBUG_MSG("[tls_client] matched a configured pin no. %zd\n", j);
			return GNUTLS_E_SUCCESS;
		}
		DEBUG_MSG("[tls_client] none of %zd configured pin(s) matched\n",
				params->pins.len);
	}

	kr_log_error(TLSCLIENT, "no pin matched: %zu pins * %d certificates\n",
			params->pins.len, cert_list_size);
	return GNUTLS_E_CERTIFICATE_ERROR;

#else /* TLS_CAN_USE_PINS */
	kr_log_error(TLSCLIENT, "internal inconsistency: TLS_CAN_USE_PINS\n");
	kr_assert(false);
	return GNUTLS_E_CERTIFICATE_ERROR;
#endif
}

/**
 * Verify that \param tls_session contains a valid X.509 certificate chain
 * with given hostname.
 *
 * \returns GNUTLS_E_SUCCESS if certificate chain is valid, any other value is an error
 */
static int client_verify_certchain(gnutls_session_t tls_session, const char *hostname)
{
	if (kr_fails_assert(hostname)) {
		kr_log_error(TLSCLIENT, "internal config inconsistency: no hostname set\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	unsigned int status;
	int ret = gnutls_certificate_verify_peers3(tls_session, hostname, &status);
	if ((ret == GNUTLS_E_SUCCESS) && (status == 0)) {
		return GNUTLS_E_SUCCESS;
	}

	if (ret == GNUTLS_E_SUCCESS) {
		gnutls_datum_t msg;
		ret = gnutls_certificate_verification_status_print(
			status, gnutls_certificate_type_get(tls_session), &msg, 0);
		if (ret == GNUTLS_E_SUCCESS) {
			kr_log_error(TLSCLIENT, "failed to verify peer certificate: "
					"%s\n", msg.data);
			gnutls_free(msg.data);
		} else {
			kr_log_error(TLSCLIENT, "failed to verify peer certificate: "
					"unable to print reason: %s (%s)\n",
					gnutls_strerror(ret), gnutls_strerror_name(ret));
		} /* gnutls_certificate_verification_status_print end */
	} else {
		kr_log_error(TLSCLIENT, "failed to verify peer certificate: "
			     "gnutls_certificate_verify_peers3 error: %s (%s)\n",
			     gnutls_strerror(ret), gnutls_strerror_name(ret));
	} /* gnutls_certificate_verify_peers3 end */
	return GNUTLS_E_CERTIFICATE_ERROR;
}

/**
 * Verify that actual TLS security parameters of \param tls_session
 * match requirements provided by user in tls_session->params.
 * \returns GNUTLS_E_SUCCESS if requirements were met, any other value is an error
 */
static int client_verify_certificate(gnutls_session_t tls_session)
{
	struct tls_client_ctx *ctx = gnutls_session_get_ptr(tls_session);
	if (kr_fails_assert(ctx->params))
		return GNUTLS_E_CERTIFICATE_ERROR;

	if (ctx->params->insecure) {
		return GNUTLS_E_SUCCESS;
	}

	gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(tls_session);
	if (cert_type != GNUTLS_CRT_X509) {
		kr_log_error(TLSCLIENT, "invalid certificate type %i has been received\n",
			     cert_type);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	unsigned int cert_list_size = 0;
	const gnutls_datum_t *cert_list =
		gnutls_certificate_get_peers(tls_session, &cert_list_size);
	if (cert_list == NULL || cert_list_size == 0) {
		kr_log_error(TLSCLIENT, "empty certificate list\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (ctx->params->pins.len > 0)
		/* check hash of the certificate but ignore everything else */
		return client_verify_pin(cert_list_size, cert_list, ctx->params);
	else
		return client_verify_certchain(ctx->c.tls_session, ctx->params->hostname);
}

struct tls_client_ctx *tls_client_ctx_new(tls_client_param_t *entry,
					    struct worker_ctx *worker)
{
	struct tls_client_ctx *ctx = calloc(1, sizeof (struct tls_client_ctx));
	if (!ctx) {
		return NULL;
	}
	unsigned int flags = GNUTLS_CLIENT | GNUTLS_NONBLOCK
#ifdef GNUTLS_ENABLE_FALSE_START
			     | GNUTLS_ENABLE_FALSE_START
#endif
	;
	int ret = gnutls_init(&ctx->c.tls_session,  flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ret = kres_gnutls_set_priority(ctx->c.tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	/* Must take a reference on parameters as the credentials are owned by it
	 * and must not be freed while the session is active. */
	++(entry->refs);
	ctx->params = entry;

	ret = gnutls_credentials_set(ctx->c.tls_session, GNUTLS_CRD_CERTIFICATE,
	                             entry->credentials);
	if (ret == GNUTLS_E_SUCCESS && entry->hostname) {
		ret = gnutls_server_name_set(ctx->c.tls_session, GNUTLS_NAME_DNS,
					entry->hostname, strlen(entry->hostname));
		kr_log_verbose("[tls_client] set hostname, ret = %d\n", ret);
	} else if (!entry->hostname) {
		kr_log_verbose("[tls_client] no hostname\n");
	}
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ctx->c.worker = worker;
	ctx->c.client_side = true;

	gnutls_transport_set_pull_function(ctx->c.tls_session, kres_gnutls_pull);
	gnutls_transport_set_vec_push_function(ctx->c.tls_session, kres_gnutls_vec_push);
	gnutls_transport_set_ptr(ctx->c.tls_session, ctx);
	return ctx;
}

void tls_client_ctx_free(struct tls_client_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->c.tls_session != NULL) {
		gnutls_deinit(ctx->c.tls_session);
		ctx->c.tls_session = NULL;
	}

	/* Must decrease the refcount for referenced parameters */
	tls_client_param_unref(ctx->params);

	free (ctx);
}

int  tls_pull_timeout_func(gnutls_transport_ptr_t h, unsigned int ms)
{
	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
	if (kr_fails_assert(t)) {
		errno = EFAULT;
		return -1;
	}
	ssize_t avail = t->nread - t->consumed;
	DEBUG_MSG("[%s] timeout check: available: %zu\n",
		  t->client_side ? "tls_client" : "tls", avail);
	if (avail <= 0) {
		errno = EAGAIN;
		return -1;
	}
	return avail;
}

int tls_client_connect_start(struct tls_client_ctx *client_ctx,
			     struct session *session,
			     tls_handshake_cb handshake_cb)
{
	if (session == NULL || client_ctx == NULL)
		return kr_error(EINVAL);

	if (kr_fails_assert(session_flags(session)->outgoing && session_get_handle(session)->type == UV_TCP))
		return kr_error(EINVAL);

	struct tls_common_ctx *ctx = &client_ctx->c;

	gnutls_session_set_ptr(ctx->tls_session, client_ctx);
	gnutls_handshake_set_timeout(ctx->tls_session, ctx->worker->engine->net.tcp.tls_handshake_timeout);
	gnutls_transport_set_pull_timeout_function(ctx->tls_session, tls_pull_timeout_func);
	session_tls_set_client_ctx(session, client_ctx);
	ctx->handshake_cb = handshake_cb;
	ctx->handshake_state = TLS_HS_IN_PROGRESS;
	ctx->session = session;

	tls_client_param_t *tls_params = client_ctx->params;
	if (tls_params->session_data.data != NULL) {
		gnutls_session_set_data(ctx->tls_session, tls_params->session_data.data,
					tls_params->session_data.size);
	}

	/* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
	while (ctx->handshake_state <= TLS_HS_IN_PROGRESS) {
		int ret = tls_handshake(ctx, handshake_cb);
		if (ret != kr_ok()) {
			return ret;
		}
	}
	return kr_ok();
}

tls_hs_state_t tls_get_hs_state(const struct tls_common_ctx *ctx)
{
	return ctx->handshake_state;
}

int tls_set_hs_state(struct tls_common_ctx *ctx, tls_hs_state_t state)
{
	if (state >= TLS_HS_LAST) {
		return kr_error(EINVAL);
	}
	ctx->handshake_state = state;
	return kr_ok();
}

int tls_client_ctx_set_session(struct tls_client_ctx *ctx, struct session *session)
{
	if (!ctx) {
		return kr_error(EINVAL);
	}
	ctx->c.session = session;
	return kr_ok();
}

#undef DEBUG_MSG
