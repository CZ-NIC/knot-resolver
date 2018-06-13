/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 *               2016-2018 CZ.NIC, z.s.p.o
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

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <uv.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "contrib/ucw/lib.h"
#include "contrib/base64.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/worker.h"

#define EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE 60*60*24*7
#define GNUTLS_PIN_MIN_VERSION  0x030400

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) kr_log_verbose("[tls] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

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
		kr_log_error("[tls] setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			     priorities, errpos - priorities, errpos, gnutls_strerror_name(err), err);
	}
	return err;
}

static ssize_t kres_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
	assert(t != NULL);

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

struct tls_ctx_t *tls_new(struct worker_ctx *worker)
{
	assert(worker != NULL);
	assert(worker->engine != NULL);

	struct network *net = &worker->engine->net;
	if (!net->tls_credentials) {
		net->tls_credentials = tls_get_ephemeral_credentials(worker->engine);
		if (!net->tls_credentials) {
			kr_log_error("[tls] X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
			return NULL;
		}
		kr_log_info("[tls] Using ephemeral TLS credentials:\n");
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
					kr_log_info("[tls] Renewed expiring ephemeral X.509 cert\n");
				} else {
					kr_log_error("[tls] Failed to renew expiring ephemeral X.509 cert, using existing one\n");
				}
			}
		} else {
			/* non-ephemeral cert: warn once when certificate expires */
			if (now >= net->tls_credentials->valid_until) {
				kr_log_error("[tls] X.509 certificate has expired!\n");
				net->tls_credentials->valid_until = GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
			}
		}
	}

	struct tls_ctx_t *tls = calloc(1, sizeof(struct tls_ctx_t));
	if (tls == NULL) {
		kr_log_error("[tls] failed to allocate TLS context\n");
		return NULL;
	}

	int err = gnutls_init(&tls->c.tls_session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error("[tls] gnutls_init(): %s (%d)\n", gnutls_strerror_name(err), err);
		tls_free(tls);
		return NULL;
	}
	tls->credentials = tls_credentials_reserve(net->tls_credentials);
	err = gnutls_credentials_set(tls->c.tls_session, GNUTLS_CRD_CERTIFICATE,
				     tls->credentials->credentials);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error("[tls] gnutls_credentials_set(): %s (%d)\n", gnutls_strerror_name(err), err);
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
	gnutls_transport_set_push_function(tls->c.tls_session, worker_gnutls_push);
	gnutls_transport_set_ptr(tls->c.tls_session, tls);

	if (net->tls_session_ticket_ctx) {
		tls_session_ticket_enable(net->tls_session_ticket_ctx,
					  tls->c.tls_session);
	}

	return tls;
}

void tls_close(struct tls_common_ctx *ctx)
{
	if (ctx == NULL || ctx->tls_session == NULL) {
		return;
	}

	assert(ctx->session);

	if (ctx->handshake_state == TLS_HS_DONE) {
		kr_log_verbose("[%s] closing tls connection to `%s`\n",
			       ctx->client_side ? "tls_client" : "tls",
			       kr_straddr(&ctx->session->peer.ip));
		ctx->handshake_state = TLS_HS_CLOSING;
		gnutls_bye(ctx->tls_session, GNUTLS_SHUT_RDWR);
	}
}

void tls_free(struct tls_ctx_t *tls)
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

int tls_push(struct qr_task *task, uv_handle_t *handle, knot_pkt_t *pkt)
{
	if (!pkt || !handle || !handle->data) {
		return kr_error(EINVAL);
	}

	struct session *session = handle->data;
	struct tls_common_ctx *tls_ctx = session->outgoing ? &session->tls_client_ctx->c :
							     &session->tls_ctx->c;

	assert (tls_ctx);
	assert (session->outgoing == tls_ctx->client_side);

	const uint16_t pkt_size = htons(pkt->size);
	const char *logstring = tls_ctx->client_side ? client_logstring : server_logstring;
	gnutls_session_t tls_session = tls_ctx->tls_session;

	tls_ctx->task = task;

	assert(gnutls_record_check_corked(tls_session) == 0);

	gnutls_record_cork(tls_session);
	ssize_t count = 0;
	if ((count = gnutls_record_send(tls_session, &pkt_size, sizeof(pkt_size)) < 0) ||
	    (count = gnutls_record_send(tls_session, pkt->wire, pkt->size) < 0)) {
		kr_log_error("[%s] gnutls_record_send failed: %s (%zd)\n",
			     logstring, gnutls_strerror_name(count), count);
		return kr_error(EIO);
	}

	ssize_t submitted = 0;
	ssize_t retries = 0;
	do {
		count = gnutls_record_uncork(tls_session, 0);
		if (count < 0) {
			if (gnutls_error_is_fatal(count)) {
				kr_log_error("[%s] gnutls_record_uncork failed: %s (%zd)\n",
				             logstring, gnutls_strerror_name(count), count);
				return kr_error(EIO);
			}
			if (++retries > TLS_MAX_UNCORK_RETRIES) {
				kr_log_error("[%s] gnutls_record_uncork: too many sequential non-fatal errors (%zd), last error is: %s (%zd)\n",
				             logstring, retries, gnutls_strerror_name(count), count);
				return kr_error(EIO);
			}
		} else if (count != 0) {
			submitted += count;
			retries = 0;
		} else if (gnutls_record_check_corked(tls_session) != 0) {
			if (++retries > TLS_MAX_UNCORK_RETRIES) {
				kr_log_error("[%s] gnutls_record_uncork: too many retries (%zd)\n",
				             logstring, retries);
				return kr_error(EIO);
			}
		} else if (submitted != sizeof(pkt_size) + pkt->size) {
			kr_log_error("[%s] gnutls_record_uncork didn't send all data(%zd of %zd)\n",
			             logstring, submitted, sizeof(pkt_size) + pkt->size);
			return kr_error(EIO);
		}
	} while (submitted != sizeof(pkt_size) + pkt->size);

	return kr_ok();
}

int tls_process(struct worker_ctx *worker, uv_stream_t *handle, const uint8_t *buf, ssize_t nread)
{
	struct session *session = handle->data;
	struct tls_common_ctx *tls_p = session->outgoing ? &session->tls_client_ctx->c :
							   &session->tls_ctx->c;
	if (!tls_p) {
		return kr_error(ENOSYS);
	}

	assert(tls_p->session == session);

	const char *logstring = tls_p->client_side ? client_logstring : server_logstring;

	tls_p->buf = buf;
	tls_p->nread = nread >= 0 ? nread : 0;
	tls_p->consumed = 0;

	/* Ensure TLS handshake is performed before receiving data. */
	while (tls_p->handshake_state == TLS_HS_IN_PROGRESS) {
		int err = gnutls_handshake(tls_p->tls_session);
		if (err == GNUTLS_E_SUCCESS) {
			tls_p->handshake_state = TLS_HS_DONE;
			kr_log_verbose("[%s] TLS handshake with %s has completed\n",
				       logstring,  kr_straddr(&session->peer.ip));
			if (tls_p->handshake_cb) {
				tls_p->handshake_cb(tls_p->session, 0);
			}
		} else if (err == GNUTLS_E_AGAIN) {
			return 0;
		} else if (gnutls_error_is_fatal(err)) {
			kr_log_verbose("[%s] gnutls_handshake failed: %s (%d)\n",
				     logstring,
			             gnutls_strerror_name(err), err);
			if (tls_p->handshake_cb) {
				tls_p->handshake_cb(tls_p->session, -1);
			}
			return kr_error(err);
		}
	}

	int submitted = 0;
	while (true) {
		ssize_t count = gnutls_record_recv(tls_p->tls_session, tls_p->recv_buf, sizeof(tls_p->recv_buf));
		if (count == GNUTLS_E_AGAIN) {
			break;    /* No data available */
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue; /* Try reading again */
		} else if (count < 0) {
			kr_log_verbose("[%s] gnutls_record_recv failed: %s (%zd)\n",
				     logstring, gnutls_strerror_name(count), count);
			return kr_error(EIO);
		}
		DEBUG_MSG("[%s] submitting %zd data to worker\n", logstring, count);
		int ret = worker_process_tcp(worker, handle, tls_p->recv_buf, count);
		if (ret < 0) {
			return ret;
		}
		if (count == 0) {
			break;
		}
		submitted += ret;
	}
	return submitted;
}

#if GNUTLS_VERSION_NUMBER >= GNUTLS_PIN_MIN_VERSION

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

	if ((err = gnutls_pubkey_init(&key)) != GNUTLS_E_SUCCESS) {
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

	if ((err = gnutls_certificate_get_crt_raw(creds, 0, 0, &data)) != GNUTLS_E_SUCCESS) {
		kr_log_error("[tls] failed to get cert to check expiration: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_init(&cert)) != GNUTLS_E_SUCCESS) {
		kr_log_error("[tls] failed to initialize cert: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}
	if ((err = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
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
	if ((err = gnutls_certificate_allocate_credentials(&tls_credentials->credentials)) != GNUTLS_E_SUCCESS) {
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
							tls_cert, tls_key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
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
	if (tls_credentials->ephemeral_servicename) {
		free(tls_credentials->ephemeral_servicename);
	}
	free(tls_credentials);
}

static int client_paramlist_entry_clear(const char *k, void *v, void *baton)
{
	struct tls_client_paramlist_entry *entry = (struct tls_client_paramlist_entry *)v;

	while (entry->ca_files.len > 0) {
		if (entry->ca_files.at[0] != NULL) {
			free((void *)entry->ca_files.at[0]);
		}
		array_del(entry->ca_files, 0);
	}

	while (entry->hostnames.len > 0) {
		if (entry->hostnames.at[0] != NULL) {
			free((void *)entry->hostnames.at[0]);
		}
		array_del(entry->hostnames, 0);
	}

	while (entry->pins.len > 0) {
		if (entry->pins.at[0] != NULL) {
			free((void *)entry->pins.at[0]);
		}
		array_del(entry->pins, 0);
	}

	array_clear(entry->ca_files);
	array_clear(entry->hostnames);
	array_clear(entry->pins);

	if (entry->credentials) {
		gnutls_certificate_free_credentials(entry->credentials);
	}

	if (entry->session_data.data) {
		gnutls_free(entry->session_data.data);
	}

	free(entry);

	return 0;
}

int tls_client_params_set(map_t *tls_client_paramlist,
			  const char *addr, uint16_t port,
			  const char *param, tls_client_param_t param_type)
{
	if (!tls_client_paramlist || !addr) {
		return kr_error(EINVAL);
	}

	/* TLS_CLIENT_PARAM_CA can be empty */
	if (param_type == TLS_CLIENT_PARAM_HOSTNAME ||
	    param_type == TLS_CLIENT_PARAM_PIN) {
		if (param == NULL || param[0] == 0) {
			return kr_error(EINVAL);
		}
	}

	/* Parameters are OK */

	char key[INET6_ADDRSTRLEN + 6];
	size_t keylen = sizeof(key);
	if (kr_straddr_join(addr, port, key, &keylen) != kr_ok()) {
		kr_log_error("[tls_client] warning: '%s' is not a valid ip address, ignoring\n", addr);
		return kr_ok();
	}

	bool is_first_entry = false;
	struct tls_client_paramlist_entry *entry = map_get(tls_client_paramlist, key);
	if (entry == NULL) {
		entry = calloc(1, sizeof(struct tls_client_paramlist_entry));
		if (entry == NULL) {
			return kr_error(ENOMEM);
		}
		is_first_entry  = true;
		int ret = gnutls_certificate_allocate_credentials(&entry->credentials);
		if (ret != GNUTLS_E_SUCCESS) {
			free(entry);
			kr_log_error("[tls_client] error: gnutls_certificate_allocate_credentials() fails (%s)\n",
				     gnutls_strerror_name(ret));
			return kr_error(ENOMEM);
		}
		gnutls_certificate_set_verify_function(entry->credentials, client_verify_certificate);
	}

	int ret = kr_ok();

	if (param_type == TLS_CLIENT_PARAM_HOSTNAME) {
		const char *hostname = param;
		bool already_exists = false;
		for (size_t i = 0; i < entry->hostnames.len; ++i) {
			if (strcmp(entry->hostnames.at[i], hostname) == 0) {
				kr_log_error("[tls_client] error: hostname '%s' for address '%s' already was set, ignoring\n", hostname, key);
				already_exists = true;
				break;
			}
		}
		if (!already_exists) {
			const char *value = strdup(hostname);
			if (!value) {
				ret = kr_error(ENOMEM);
			} else if (array_push(entry->hostnames, value) < 0) {
				free ((void *)value);
				ret = kr_error(ENOMEM);
			}
		}
	} else if (param_type == TLS_CLIENT_PARAM_CA) {
		/* Import ca files only when hostname is already set */
		if (entry->hostnames.len == 0) {
			return kr_error(ENOENT);
		}
		const char *ca_file = param;
		bool already_exists = false;
		for (size_t i = 0; i < entry->ca_files.len; ++i) {
			const char *imported_ca = entry->ca_files.at[i];
			if (imported_ca[0] == 0 && (ca_file == NULL || ca_file[0] == 0)) {
				kr_log_error("[tls_client] error: system ca for address '%s' already was set, ignoring\n", key);
				already_exists = true;
				break;
			} else if (strcmp(imported_ca, ca_file) == 0) {
				kr_log_error("[tls_client] error: ca file '%s' for address '%s' already was set, ignoring\n", ca_file, key);
				already_exists = true;
				break;
			}
		}
		if (!already_exists) {
			const char *value = strdup(ca_file != NULL ? ca_file : "");
			if (!value) {
				ret = kr_error(ENOMEM);
			} else if (array_push(entry->ca_files, value) < 0) {
				free ((void *)value);
				ret = kr_error(ENOMEM);
			} else if (value[0] == 0) {
				int res = gnutls_certificate_set_x509_system_trust (entry->credentials);
				if (res <= 0) {
					kr_log_error("[tls_client] failed to import certs from system store (%s)\n",
						     gnutls_strerror_name(res));
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported %d certs from system store\n", res);
				}
			} else {
				int res = gnutls_certificate_set_x509_trust_file(entry->credentials, value,
										 GNUTLS_X509_FMT_PEM);
				if (res <= 0) {
					kr_log_error("[tls_client] failed to import certificate file '%s' (%s)\n",
						     value, gnutls_strerror_name(res));
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported %d certs from file '%s'\n",
							res, value);

				}
			}
		}
	} else if (param_type == TLS_CLIENT_PARAM_PIN) {
		const char *pin = param;
		for (size_t i = 0; i < entry->pins.len; ++i) {
			if (strcmp(entry->pins.at[i], pin) == 0) {
				kr_log_error("[tls_client] warning: pin '%s' for address '%s' already was set, ignoring\n", pin, key);
				return kr_ok();
			}
		}
		const void *value = strdup(pin);
		if (!value) {
			ret = kr_error(ENOMEM);
		} else if (array_push(entry->pins, value) < 0) {
			free ((void *)value);
			ret = kr_error(ENOMEM);
		}
	}

	if ((ret == kr_ok()) && is_first_entry) {
		bool fail = (map_set(tls_client_paramlist, key, entry) != 0);
		if (fail) {
			ret = kr_error(ENOMEM);
		}
	}

	if ((ret != kr_ok()) && is_first_entry) {
		client_paramlist_entry_clear(NULL, (void *)entry, NULL);
	}

	return ret;
}

int tls_client_params_free(map_t *tls_client_paramlist)
{
	if (!tls_client_paramlist) {
		return kr_error(EINVAL);
	}

	map_walk(tls_client_paramlist, client_paramlist_entry_clear, NULL);
	map_clear(tls_client_paramlist);

	return kr_ok();
}

static int client_verify_certificate(gnutls_session_t tls_session)
{
	struct tls_client_ctx_t *ctx = gnutls_session_get_ptr(tls_session);
	assert(ctx->params != NULL);

	if (ctx->params->pins.len == 0 && ctx->params->ca_files.len == 0) {
		return GNUTLS_E_SUCCESS;
	}

	gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(tls_session);
	if (cert_type != GNUTLS_CRT_X509) {
		kr_log_error("[tls_client] invalid certificate type %i has been received\n",
			     cert_type);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	unsigned int cert_list_size = 0;
	const gnutls_datum_t *cert_list =
		gnutls_certificate_get_peers(tls_session, &cert_list_size);
	if (cert_list == NULL || cert_list_size == 0) {
		kr_log_error("[tls_client] empty certificate list\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

#if GNUTLS_VERSION_NUMBER >= GNUTLS_PIN_MIN_VERSION
	if (ctx->params->pins.len == 0) {
		DEBUG_MSG("[tls_client] skipping certificate PIN check\n");
		goto skip_pins;
	}

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

		char cert_pin[PINLEN] = { 0 };
		ret = get_oob_key_pin(cert, cert_pin, sizeof(cert_pin));

		gnutls_x509_crt_deinit(cert);

		if (ret != GNUTLS_E_SUCCESS) {
			return ret;
		}

		DEBUG_MSG("[tls_client] received pin  : %s\n", cert_pin);
		for (size_t i = 0; i < ctx->params->pins.len; ++i) {
			const char *pin = ctx->params->pins.at[i];
			bool match = (strcmp(cert_pin, pin) == 0);
			DEBUG_MSG("[tls_client] configured pin: %s matches? %s\n",
				  pin, match ? "yes" : "no");
			if (match) {
				return GNUTLS_E_SUCCESS;
			}
		}
	}

	/* pins were set, but no one was not matched */
	kr_log_error("[tls_client] certificate PIN check failed\n");
#else
	if (ctx->params->pins.len != 0) {
		kr_log_error("[tls_client] newer gnutls is required to use PIN check\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
#endif

skip_pins:

	if (ctx->params->ca_files.len == 0) {
		DEBUG_MSG("[tls_client] empty CA files list\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (ctx->params->hostnames.len == 0) {
		DEBUG_MSG("[tls_client] empty hostname list\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	int ret;
	unsigned int status;
	for (size_t i = 0; i < ctx->params->hostnames.len; ++i) {
		ret = gnutls_certificate_verify_peers3(
				ctx->c.tls_session,
				ctx->params->hostnames.at[i],
				&status);
		if ((ret == GNUTLS_E_SUCCESS) && (status == 0)) {
			return GNUTLS_E_SUCCESS;
		}
	}

	if (ret == GNUTLS_E_SUCCESS) {
		gnutls_datum_t msg;
		ret = gnutls_certificate_verification_status_print(
			status, gnutls_certificate_type_get(ctx->c.tls_session), &msg, 0);
		if (ret == GNUTLS_E_SUCCESS) {
			kr_log_error("[tls_client] failed to verify peer certificate: "
					"%s\n", msg.data);
			gnutls_free(msg.data);
		} else {
			kr_log_error("[tls_client] failed to verify peer certificate: "
					"unable to print reason: %s (%s)\n",
					gnutls_strerror(ret), gnutls_strerror_name(ret));
		} /* gnutls_certificate_verification_status_print end */
	} else {
		kr_log_error("[tls_client] failed to verify peer certificate: "
			     "gnutls_certificate_verify_peers3 error: %s (%s)\n",
			     gnutls_strerror(ret), gnutls_strerror_name(ret));
	} /* gnutls_certificate_verify_peers3 end */
	return GNUTLS_E_CERTIFICATE_ERROR;
}

struct tls_client_ctx_t *tls_client_ctx_new(const struct tls_client_paramlist_entry *entry,
					    struct worker_ctx *worker)
{
	struct tls_client_ctx_t *ctx = calloc(1, sizeof (struct tls_client_ctx_t));
	if (!ctx) {
		return NULL;
	}

	int ret = gnutls_init(&ctx->c.tls_session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ret = kres_gnutls_set_priority(ctx->c.tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ret = gnutls_credentials_set(ctx->c.tls_session, GNUTLS_CRD_CERTIFICATE,
	                             entry->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ctx->c.worker = worker;
	ctx->c.client_side = true;

	gnutls_transport_set_pull_function(ctx->c.tls_session, kres_gnutls_pull);
	gnutls_transport_set_push_function(ctx->c.tls_session, worker_gnutls_push);
	gnutls_transport_set_ptr(ctx->c.tls_session, ctx);
	return ctx;
}

void tls_client_ctx_free(struct tls_client_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->c.tls_session != NULL) {
		gnutls_deinit(ctx->c.tls_session);
		ctx->c.tls_session = NULL;
	}

	free (ctx);
}

int tls_client_connect_start(struct tls_client_ctx_t *client_ctx,
			     struct session *session,
			     tls_handshake_cb handshake_cb)
{
	if (session == NULL || client_ctx == NULL) {
		return kr_error(EINVAL);
	}

	assert(session->outgoing && session->handle->type == UV_TCP);

	struct tls_common_ctx *ctx = &client_ctx->c;

	gnutls_session_set_ptr(ctx->tls_session, client_ctx);
	gnutls_handshake_set_timeout(ctx->tls_session, KR_CONN_RTT_MAX * 3);
	session->tls_client_ctx = client_ctx;
	ctx->handshake_cb = handshake_cb;
	ctx->handshake_state = TLS_HS_IN_PROGRESS;
	ctx->session = session;

	struct tls_client_paramlist_entry *tls_params = client_ctx->params;
	if (tls_params->session_data.data != NULL) {
		gnutls_session_set_data(ctx->tls_session, tls_params->session_data.data,
					tls_params->session_data.size);
	}

	int ret = gnutls_handshake(ctx->tls_session);
	if (ret == GNUTLS_E_SUCCESS) {
		return kr_ok();
	} else if (gnutls_error_is_fatal(ret) != 0) {
		kr_log_verbose("[tls_client] handshake failed (%s)\n", gnutls_strerror(ret));
		return kr_error(ECONNABORTED);
	}
	return kr_error(EAGAIN);
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

int tls_client_ctx_set_params(struct tls_client_ctx_t *ctx,
			      struct tls_client_paramlist_entry *entry,
			      struct session *session)
{
	if (!ctx) {
		return kr_error(EINVAL);
	}
	ctx->params = entry;
	ctx->c.session = session;
	return kr_ok();
}

#undef DEBUG_MSG
