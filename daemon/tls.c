/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 *               2016 CZ.NIC, z.s.p.o
 * 
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 *                 Ondřej Surý <ondrej@sury.org>
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
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <uv.h>

#include <contrib/ucw/lib.h>
#include "contrib/base64.h"
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
	struct tls_credentials *credentials;
};

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) fprintf(stderr, "[tls] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

static void kres_gnutls_log(int level, const char *message)
{
	kr_log_error("[tls] gnutls: (%d) %s", level, message);
}

void tls_setup_logging(bool verbose)
{
	gnutls_global_set_log_function(kres_gnutls_log);
	gnutls_global_set_log_level(verbose ? 1 : 0);
}

static ssize_t kres_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	const uv_buf_t ub = {(void *)buf, len};

	DEBUG_MSG("[tls] push %zu <%p>\n", len, h);
	if (t == NULL) {
		errno = EFAULT;
		return -1;
	}

	int ret = uv_try_write(t->handle, &ub, 1);
	if (ret > 0) {
		return (ssize_t) ret;
	}
	if (ret == UV_EAGAIN) {
		errno = EAGAIN;
	} else {
		kr_log_error("[tls] uv_try_write: %s\n", uv_strerror(ret));
		errno = EIO;
	}
	return -1;
}


static ssize_t kres_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_ctx_t *t = (struct tls_ctx_t *)h;
	assert(t != NULL);

	ssize_t	avail = t->nread - t->consumed;
	DEBUG_MSG("[tls] pull wanted: %zu available: %zu\n", len, avail);
	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		return -1;
	}

	ssize_t	transfer = MIN(avail, len);
	memcpy(buf, t->buf + t->consumed, transfer);
	t->consumed += transfer;
	return transfer;
}

struct tls_ctx_t *tls_new(struct worker_ctx *worker)
{
	assert(worker != NULL);
	assert(worker->engine != NULL);

	struct network *net = &worker->engine->net;
	if (!net->tls_credentials) {
		kr_log_error("[tls] x509 credentials are missing; no TLS\n");
		return NULL;
	}

	time_t now = time(NULL);
	if (net->tls_credentials->valid_until != GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION &&
	    now >= net->tls_credentials->valid_until) {
		/* Warn once when certificate expires */
		kr_log_error("[tls] X.509 certificate has expired!\n");
		net->tls_credentials->valid_until = GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
	}

	struct tls_ctx_t *tls = calloc(1, sizeof(struct tls_ctx_t));
	if (tls == NULL) {
		kr_log_error("[tls] failed to allocate TLS context\n");
		return NULL;
	}

	int err = gnutls_init(&tls->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (err < 0) {
		kr_log_error("[tls] gnutls_init(): %s (%d)\n", gnutls_strerror_name(err), err);
		tls_free(tls);
		return NULL;
	}
	tls->credentials = tls_credentials_reserve(net->tls_credentials);
	err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE, tls->credentials->credentials);
	if (err < 0) {
		kr_log_error("[tls] gnutls_credentials_set(): %s (%d)\n", gnutls_strerror_name(err), err);
		tls_free(tls);
		return NULL;
	}
	const char *errpos = NULL;
	err = gnutls_priority_set_direct(tls->session, priorities, &errpos);
	if (err < 0) {
		kr_log_error("[tls] setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			     priorities, errpos - priorities, errpos, gnutls_strerror_name(err), err);
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
		/* Don't terminate TLS connection, just tear it down */
		gnutls_deinit(tls->session);
		tls->session = NULL;
	}

	tls_credentials_release(tls->credentials);
	free(tls);
}

int tls_push(struct qr_task *task, uv_handle_t *handle, knot_pkt_t *pkt)
{
	if (!pkt || !handle || !handle->data) {
		return kr_error(EINVAL);
	}

	struct session *session = handle->data;
	const uint16_t pkt_size = htons(pkt->size);
	struct tls_ctx_t *tls_p = session->tls_ctx;
	if (!tls_p) {
		kr_log_error("[tls] no tls context on push\n");
		return kr_error(ENOENT);
	}

	gnutls_record_cork(tls_p->session);
	ssize_t count = 0;
	if ((count = gnutls_record_send(tls_p->session, &pkt_size, sizeof(pkt_size)) < 0) ||
	    (count = gnutls_record_send(tls_p->session, pkt->wire, pkt->size) < 0)) {
		kr_log_error("[tls] gnutls_record_send failed: %s (%zd)\n", gnutls_strerror_name(count), count);
		return kr_error(EIO);
	}

	ssize_t submitted = 0;
	do {
		count = gnutls_record_uncork(tls_p->session, 0);
		if (count < 0) {
			if (gnutls_error_is_fatal(count)) {
				kr_log_error("[tls] gnutls_record_uncork failed: %s (%zd)\n",
				             gnutls_strerror_name(count), count);
				return kr_error(EIO);
			}
		} else {
			submitted += count;
			if (count == 0 && submitted != sizeof(pkt_size) + pkt->size) {
				kr_log_error("[tls] gnutls_record_uncork didn't send all data: %s (%zd)\n",
				             gnutls_strerror_name(count), count);
				return kr_error(EIO);
			}
		}
	} while (submitted != sizeof(pkt_size) + pkt->size);
	
	return kr_ok();
}

int tls_process(struct worker_ctx *worker, uv_stream_t *handle, const uint8_t *buf, ssize_t nread)
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

	/* Ensure TLS handshake is performed before receiving data. */
	while (!tls_p->handshake_done) {
		int err = gnutls_handshake(tls_p->session);
		if (err == GNUTLS_E_SUCCESS) {
			tls_p->handshake_done = true;
		} else if (err == GNUTLS_E_AGAIN) {
			return 0; /* No data, bail out */
		} else if (err < 0 && gnutls_error_is_fatal(err)) {
			return kr_error(err);
		}
	}

	int submitted = 0;
	while (true) {
		ssize_t count = gnutls_record_recv(tls_p->session, tls_p->recv_buf, sizeof(tls_p->recv_buf));
		if (count == GNUTLS_E_AGAIN) {
			break;    /* No data available */
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue; /* Try reading again */
		} else if (count < 0) {
			kr_log_error("[tls] gnutls_record_recv failed: %s (%zd)\n",
			             gnutls_strerror_name(count), count);
			return kr_error(EIO);
		}
		DEBUG_MSG("[tls] submitting %zd data to worker\n", count);
		int ret = worker_process_tcp(worker, handle, tls_p->recv_buf, count);
		if (ret < 0) {
			return ret;
		}
		submitted += ret;
	}
	return submitted;
}

#if GNUTLS_VERSION_NUMBER >= 0x030400

/*
  DNS-over-TLS Out of band key-pinned authentication profile uses the
  same form of pins as HPKP:
  
  e.g.  pin-sha256="FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVI="
  
  DNS-over-TLS OOB key-pins: https://tools.ietf.org/html/rfc7858#appendix-A
  HPKP pin reference:        https://tools.ietf.org/html/rfc7469#appendix-A
*/
#define PINLEN  (((32) * 8 + 4)/6) + 3 + 1

/* out must be at least PINLEN octets long */
static int get_oob_key_pin(gnutls_x509_crt_t crt, char *outchar, ssize_t outchar_len)
{
	int err;
	gnutls_pubkey_t key;
	gnutls_datum_t datum = { .size = 0 };

	if ((err = gnutls_pubkey_init(&key)) < 0) {
		return err;
	}

	if ((err = gnutls_pubkey_import_x509(key, crt, 0)) != GNUTLS_E_SUCCESS) {
		goto leave;
	} else {
		if ((err = gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &datum)) != GNUTLS_E_SUCCESS) {
			goto leave;
		} else {
			uint8_t raw_pin[32];
			if ((err = gnutls_hash_fast(GNUTLS_DIG_SHA256, datum.data, datum.size, raw_pin)) != GNUTLS_E_SUCCESS) {
				goto leave;
			} else {
				base64_encode(raw_pin, sizeof(raw_pin), (uint8_t *)outchar, outchar_len);
			}
		}
	}
leave:
	gnutls_free(datum.data);
	gnutls_pubkey_deinit(key);
	return err;
}

void tls_credentials_log_pins(struct tls_credentials *tls_credentials)
{
	for (int index = 0;; index++) {
		int err;
		gnutls_x509_crt_t *certs = NULL;
		unsigned int cert_count = 0;

		if ((err = gnutls_certificate_get_x509_crt(tls_credentials->credentials, index, &certs, &cert_count)) != GNUTLS_E_SUCCESS) {
			if (err != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
				kr_log_error("[tls] could not get X.509 certificates (%d) %s\n", err, gnutls_strerror_name(err));
			}
			return;
		}

		for (int i = 0; i < cert_count; i++) {
			char pin[PINLEN] = { 0 };
			if ((err = get_oob_key_pin(certs[i], pin, sizeof(pin))) != GNUTLS_E_SUCCESS) {
				kr_log_error("[tls] could not calculate RFC 7858 OOB key-pin from cert %d (%d) %s\n", i, err, gnutls_strerror_name(err));
			} else {
				kr_log_info("[tls] RFC 7858 OOB key-pin (%d): pin-sha256=\"%s\"\n", i, pin);
			}
			gnutls_x509_crt_deinit(certs[i]);
		}
		gnutls_free(certs);
	}
}
#else
void tls_credentials_log_pins(struct tls_credentials *tls_credentials)
{
	kr_log_error("[tls] could not calculate RFC 7858 OOB key-pin; GnuTLS 3.4.0+ required\n");
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

	if ((err = gnutls_certificate_get_crt_raw(creds, 0, 0, &data)) < 0) {
		kr_log_error("[tls] failed to get cert to check expiration: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_init(&cert)) < 0) {
		kr_log_error("[tls] failed to initialize cert: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER)) < 0) {
		kr_log_error("[tls] failed to construct cert while checking expiration: (%d) %s\n",
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
	if ((err = gnutls_certificate_allocate_credentials(&tls_credentials->credentials)) < 0) {
		kr_log_error("[tls] gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}
	if ((err = gnutls_certificate_set_x509_system_trust(tls_credentials->credentials)) < 0) {
		if (err != GNUTLS_E_UNIMPLEMENTED_FEATURE) {
			kr_log_error("[tls] warning: gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
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
							tls_cert, tls_key, GNUTLS_X509_FMT_PEM)) < 0) {
		tls_credentials_free(tls_credentials);
		kr_log_error("[tls] gnutls_certificate_set_x509_key_file(%s,%s) failed: %d (%s)\n",
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
	free(tls_credentials);
}

#undef DEBUG_MSG
