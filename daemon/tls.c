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

#include <openssl/ssl.h>
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

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) kr_log_verbose("[tls] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

static char const server_logstring[] = "tls";
static char const client_logstring[] = "tls_client";
/*
static void tls_ex_data_params_free(void *parent, void *ptr,
	    CRYPTO_EX_DATA *ad, int index,
	    long argl, void *argp) {
	tls_
  OPENSSL_free(state);
}

static CRYPTO_once_t g_ssl_test_ticket_aead_ex_index_once = CRYPTO_ONCE_INIT;
static int g_ssl_test_ticket_aead_ex_index;
*/
static int tls_ex_data_params_index = -1;

static enum ssl_verify_result_t client_verify_certificate(SSL *tls_session, uint8_t *out_alert);

/**
 * Set mandatory security settings from
 * https://tools.ietf.org/html/draft-ietf-dprive-dtls-and-tls-profiles-11#section-9
 * Performance optimizations are not implemented at the moment.
 */
static int kres_tls_set_priority(SSL *ssl) {
	static const char * const priorities = SSL_DEFAULT_CIPHER_LIST;

	/* BoringSSL's default is "ALL" */
	if (!SSL_set_strict_cipher_list(ssl, priorities)) {
		kr_log_error("[tls] setting cipher list failed");
		kr_error(EINVAL);
	}

	/* TLS 1.2 and higher */
	if (!SSL_set_min_proto_version(ssl, TLS1_2_VERSION)) {
		kr_log_error("[tls] setting minimum protocol version to TLS 1.2 failed");
		kr_error(EINVAL);
	}

	return kr_ok();
}

int tls_read_from_write_bio(struct tls_common_ctx *ctx) {
	int bytes_read = 0;
	int bytes_to_read = 0;
	while ((bytes_to_read = BIO_pending(ctx->write_bio)) > 0) {
		if (bytes_to_read > sizeof(ctx->recv_buf)) {
			bytes_to_read = sizeof(ctx->recv_buf);
		}
		bytes_read = BIO_read(ctx->write_bio, (char *)ctx->recv_buf, bytes_to_read);
		if (bytes_read < 0) {
			kr_log_error("[tls] failed to read to write BIO\n");
			return kr_error(EIO);
		}
		worker_tls_push(ctx, ctx->recv_buf, bytes_read);
	}
	return kr_ok();
}

int tls_write_to_read_bio(struct tls_common_ctx *ctx) {
	int count = 0;
	if ((count = BIO_write(ctx->read_bio, ctx->buf, ctx->nread)) < 0) {
		kr_log_error("[tls] failed to write to read BIO\n");
		return kr_error(EIO);
	}
	return kr_ok();
}

/** Perform TLS handshake and handle error codes according to the documentation.
  * See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_do_handshake
  * The function returns kr_ok() or success or non fatal error, kr_error(EAGAIN) on blocking, or kr_error(EIO) on fatal error.
  */
static int tls_handshake(struct tls_common_ctx *ctx, tls_handshake_cb handshake_cb) {
	struct session *session = ctx->session;
	const char *logstring = ctx->client_side ? client_logstring : server_logstring;

	int success = SSL_do_handshake(ctx->tls_session);
	int error = SSL_get_error(ctx->tls_session, success);
	tls_read_from_write_bio(ctx);

	if (success == 1 && SSL_is_init_finished(ctx->tls_session)) {
		/* Handshake finished, return success */
		ctx->handshake_state = TLS_HS_DONE;
		kr_log_verbose("[%s] TLS handshake with %s has completed\n",
				logstring,  kr_straddr(&session->peer.ip));
		if (ctx->handshake_cb) {
			ctx->handshake_cb(session, 0);
		}
	} else {
		if (error == SSL_ERROR_WANT_READ ||
			error == SSL_ERROR_WANT_WRITE) {
			kr_log_verbose("[%s] TLS handshake retry\n", logstring);
			return kr_error(EAGAIN);
		} else {
			kr_log_verbose("[%s] TLS handshake failed (%d)\n",
				logstring, error);
			if (ctx->handshake_cb) {
				ctx->handshake_cb(session, -1);
			}
			return kr_error(EIO);
		}
	}
	return kr_ok();
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
	if (net->tls_credentials->valid_until != (time_t)-1) {
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
				net->tls_credentials->valid_until = (time_t)-1;
			}
		}
	}

	struct tls_ctx_t *tls = calloc(1, sizeof(struct tls_ctx_t));
	if (tls == NULL) {
		kr_log_error("[tls] failed to allocate TLS context\n");
		return NULL;
	}

	tls->c.tls_session = SSL_new(net->ssl_ctx);
	SSL_set_accept_state(tls->c.tls_session);

	tls->credentials = tls_credentials_reserve(net->tls_credentials);
	if (!SSL_set1_chain(tls->c.tls_session, tls->credentials->tls_cert_chain)) {
		kr_log_error("[tls] failed to set certificate chain\n");
		tls_free(tls);
		return NULL;
	}

	if (!SSL_use_certificate(tls->c.tls_session, sk_X509_value(tls->credentials->tls_cert_chain, sk_X509_num(tls->credentials->tls_cert_chain)-1))) {
		kr_log_error("[tls] failed to set leaf certificate\n");
		tls_free(tls);
		return NULL;
	}

	if (!SSL_use_PrivateKey(tls->c.tls_session, tls->credentials->tls_key)) {
		kr_log_error("[tls] failed to set private key\n");
		return NULL;
	}

	if (kres_tls_set_priority(tls->c.tls_session) != kr_ok()) {
		kr_log_error("[tls] failed to set cipher suite and protocol priority\n");
		tls_free(tls);
		return NULL;
	}

	if (!SSL_check_private_key(tls->c.tls_session)) {
		kr_log_error("[tls] certificate and key are not consistent\n");
		tls_free(tls);
		return NULL;
	}

	tls->c.worker = worker;
	tls->c.client_side = false;

	tls->c.read_bio = BIO_new(BIO_s_mem());
	tls->c.write_bio = BIO_new(BIO_s_mem());
	BIO_set_nbio(tls->c.read_bio, 1);
	BIO_set_nbio(tls->c.write_bio, 1);
	SSL_set_bio(tls->c.tls_session, tls->c.read_bio, tls->c.write_bio);

	if (net->tls_session_ticket_ctx) {
		tls_session_ticket_enable(net->tls_session_ticket_ctx,
					  SSL_get_SSL_CTX(tls->c.tls_session));
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
		SSL_shutdown(ctx->tls_session);
	}
}

void tls_free(struct tls_ctx_t *tls)
{
	if (!tls) {
		return;
	}

	if (tls->c.tls_session) {
		/* Don't terminate TLS connection, just tear it down */
		SSL_free(tls->c.tls_session);
		tls->c.tls_session = NULL;
		tls->c.read_bio = NULL;
		tls->c.write_bio = NULL;
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
	SSL *tls_session = tls_ctx->tls_session;

	tls_ctx->task = task;

	ssize_t retries;
	ssize_t submitted;
	ssize_t count;

	/* This costs a copy, but prevents SSL_write from creating separate
	 * TLS records for the packet size and the packet data. */
	const size_t payload_size = sizeof(pkt_size) + pkt->size;
	char *payload = OPENSSL_malloc(payload_size);

	if (!payload) {
		return kr_error(ENOMEM);
	}

	memcpy(payload, &pkt_size, sizeof(pkt_size));
	memcpy(payload + sizeof(pkt_size), pkt->wire, pkt->size);

	for (retries = 0, submitted = 0; submitted < payload_size; submitted += count) {
		count = SSL_write(tls_session, payload + submitted, payload_size - submitted);
		if (count <= 0) {
			if (++retries > TLS_MAX_UNCORK_RETRIES) {
				kr_log_error("[%s] SSL_write: too many retries writing pkt_size (%zd)\n",
				             logstring, retries);
				return kr_error(EIO);
			}
			else {
				count = 0;
			}
		}
	}

	OPENSSL_free(payload);

	tls_read_from_write_bio(tls_ctx);

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

	tls_write_to_read_bio(tls_p);

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
	int submitted = 0;
	bool is_retrying = false;
	uint64_t retrying_start = 0;
	while (BIO_pending(tls_p->read_bio) > 0) {
		int count = SSL_read(tls_p->tls_session, tls_p->recv_buf, sizeof(tls_p->recv_buf));
		int error = SSL_get_error(tls_p->tls_session, count);
		if (count < 0) {
			/* Retry on non-fatal errors (alerts, rehandshake) */
			if (error == SSL_ERROR_WANT_READ) {
				if (!is_retrying) {
					is_retrying = true;
					retrying_start = kr_now();
				}
				uint64_t elapsed = kr_now() - retrying_start;
				if (elapsed < TLS_MAX_HANDSHAKE_TIME) {
					continue; /* Try reading again */
				}
			}

			kr_log_verbose("[%s] SSL_read failed: %s (%d)\n",
					logstring, ERR_error_string(ERR_get_error(), NULL), error);

			/* Propagate errors to lower layer */
			count = kr_error(EIO);
		}

		DEBUG_MSG("[%s] submitting %zd data to worker\n", logstring, count);
		int ret = worker_process_tcp(worker, handle, tls_p->recv_buf, count);
		if (ret < 0) {
			return ret;
		}
		if (count <= 0) {
			break;
		}
		submitted += ret;
	}
	return submitted;
}

/*
  DNS-over-TLS Out of band key-pinned authentication profile uses the
  same form of pins as HPKP:

  e.g.  pin-sha256="FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVI="

  DNS-over-TLS OOB key-pins: https://tools.ietf.org/html/rfc7858#appendix-A
  HPKP pin reference:        https://tools.ietf.org/html/rfc7469#appendix-A
*/
#define PINLEN  (((32) * 8 + 4)/6) + 3 + 1

/* out must be at least PINLEN octets long */
static int get_oob_key_pin(X509 *crt, char *outchar, ssize_t outchar_len)
{
	EVP_PKEY *key = X509_get_pubkey(crt);
	CBB *cbb = OPENSSL_malloc(sizeof(*cbb));
	uint8_t *data = NULL;
	size_t data_len = 0;

	if (key == NULL) {
		goto leave;
	}

	if (!CBB_init(cbb, 256)) {
		goto leave;
	}

	if (!EVP_marshal_public_key(cbb, key)) {
		goto leave;
	}

	if (!CBB_finish(cbb, &data, &data_len)) {
		goto leave;
	}

	uint8_t raw_pin[32];
	if (!EVP_Digest(data, data_len, raw_pin, NULL, EVP_sha256(), NULL)) {
		goto leave;
	}

	EVP_EncodeBlock((uint8_t *)outchar, raw_pin, sizeof(raw_pin));
	EVP_PKEY_free(key);
	OPENSSL_free(data);
	CBB_cleanup(cbb);
	return kr_ok();

leave:
	EVP_PKEY_free(key);
	OPENSSL_free(data);
	CBB_cleanup(cbb);
	return kr_error(EINVAL);
}

void tls_credentials_log_pins(struct tls_credentials *tls_credentials)
{
	unsigned int cert_count = sk_X509_num(tls_credentials->tls_cert_chain);

	for (int i = 0; i < cert_count; i++) {
		char pin[PINLEN] = { 0 };
		X509 *cert = sk_X509_value(tls_credentials->tls_cert_chain, i);
		if (get_oob_key_pin(cert, pin, sizeof(pin)) != kr_ok()) {
			kr_log_error("[tls] could not calculate RFC 7858 OOB key-pin from cert %d\n", i);
		} else {
			kr_log_info("[tls] RFC 7858 OOB key-pin (%d): pin-sha256=\"%s\"\n", i, pin);
		}
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

static time_t _get_end_entity_expiration(X509 *cert)
{
	time_t ret = (time_t)-1;
	ASN1_TIME *asn1_expiration_time = X509_get_notAfter(cert);
	ASN1_TIME *asn1_unix_epoch = ASN1_TIME_new();
	int days, seconds;

	if (asn1_unix_epoch == NULL) {
		kr_log_error("[tls] ASN1_TIME_new() failed\n");
		goto done;
	}

	if (asn1_expiration_time == NULL) {
		kr_log_error("[tls] expiration date of certificate is NULL\n");
		goto done;
	}

	if (!ASN1_TIME_set(asn1_unix_epoch, (time_t)0)) {
		kr_log_error("[tls] failed to convert 0 to ASN1 time\n");
	}

	if (!ASN1_TIME_diff(&days, &seconds, asn1_unix_epoch, asn1_expiration_time)) {
		kr_log_error("[tls] ASN1_TIME_diff failed\n");
		goto done;
	}

	ret = (time_t)(days * 3600 + seconds);
 done:
	ASN1_TIME_free(asn1_unix_epoch);
	return ret;
}

int tls_certificate_set(struct network *net, const char *tls_cert_file, const char *tls_key_file)
{
	if (!net || !net->ssl_ctx) {
		return kr_error(EINVAL);
	}

	struct tls_credentials *tls_credentials = calloc(1, sizeof(*tls_credentials));
	if (tls_credentials == NULL) {
		return kr_error(ENOMEM);
	}

	if (!SSL_CTX_set_default_verify_paths(net->ssl_ctx)) {
		kr_log_error("[tls] failed to load system-default trusted CA certificates\n");
		tls_credentials_free(tls_credentials);
		return kr_error(EIO);
	}

	if ((str_replace(&tls_credentials->tls_cert_file, tls_cert_file) != 0) ||
		(str_replace(&tls_credentials->tls_key_file, tls_key_file) != 0)) {
		tls_credentials_free(tls_credentials);
		return kr_error(ENOMEM);
	}

	if (!SSL_CTX_use_certificate_file(net->ssl_ctx, tls_cert_file, SSL_FILETYPE_PEM)) {
		tls_credentials_free(tls_credentials);
		kr_log_error("[tls] SSL_CTX_use_certificate_file(...,%s,...) failed\n", tls_cert_file);
		return kr_error(EINVAL);
	}

	if (!SSL_CTX_use_PrivateKey_file(net->ssl_ctx, tls_key_file, SSL_FILETYPE_PEM)) {
		tls_credentials_free(tls_credentials);
		kr_log_error("[tls] SSL_CTX_use_PrivateKey_file(...,%s,...) failed\n", tls_key_file);
		return kr_error(EINVAL);
	}

	tls_credentials->tls_key = SSL_CTX_get0_privatekey(net->ssl_ctx);

	SSL_CTX_get0_chain_certs(net->ssl_ctx, &tls_credentials->tls_cert_chain);

	/* record the expiration date: */

	STACK_OF(X509) *chain = tls_credentials->tls_cert_chain;
	X509 *leafcrt = sk_X509_value(chain, sk_X509_num(chain));
	tls_credentials->valid_until = _get_end_entity_expiration(leafcrt);

	/* Exchange the x509 credentials */
	struct tls_credentials *old_credentials = net->tls_credentials;

	/* Start using the new x509_credentials */
	net->tls_credentials = tls_credentials;
	tls_credentials_log_pins(net->tls_credentials);

	if (old_credentials) {
		int err = tls_credentials_release(old_credentials);
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

	sk_X509_pop_free(tls_credentials->tls_cert_chain, X509_free);

	EVP_PKEY_free(tls_credentials->tls_key);

	if (tls_credentials->tls_cert_file) {
		free(tls_credentials->tls_cert_file);
	}
	if (tls_credentials->tls_key_file) {
		free(tls_credentials->tls_key_file);
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

	sk_X509_pop_free(entry->tls_cert_chain, X509_free);
	EVP_PKEY_free(entry->tls_key);
	SSL_SESSION_free(entry->session_data);

	free(entry);

	return 0;
}

int tls_client_params_set(SSL_CTX *ssl_ctx, map_t *tls_client_paramlist,
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
		if (tls_ex_data_params_index == -1) {
			tls_ex_data_params_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		}
		SSL_CTX_set_ex_data(ssl_ctx, tls_ex_data_params_index, entry);
		SSL_CTX_set_custom_verify(ssl_ctx, SSL_VERIFY_PEER, client_verify_certificate);
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
				if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
					kr_log_error("[tls_client] failed to import certs from system store\n");
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported certs from system store\n");
				}
			} else {
				if (!SSL_CTX_load_verify_locations(ssl_ctx, value, NULL)) {
					kr_log_error("[tls_client] failed to import certificate file '%s'\n", value);
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported certs from file '%s'\n", value);

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

static enum ssl_verify_result_t client_verify_certificate(SSL *tls_session, uint8_t *out_alert)
{
	struct tls_client_paramlist_entry *params = (struct tls_client_paramlist_entry *)SSL_CTX_get_ex_data(SSL_get_SSL_CTX(tls_session), tls_ex_data_params_index);

	assert(params != NULL);

	if (params->pins.len == 0 && params->ca_files.len == 0) {
		return ssl_verify_ok;
	}

	STACK_OF(X509) *cert_list = SSL_get_peer_cert_chain(tls_session);
	unsigned int cert_list_size = sk_X509_num(cert_list);

	if (cert_list == NULL || cert_list_size == 0) {
		kr_log_error("[tls_client] empty certificate list\n");
		return ssl_verify_invalid;
	}

	if (params->pins.len == 0) {
		DEBUG_MSG("[tls_client] skipping certificate PIN check\n");
		goto skip_pins;
	}

	for (int i = 0; i < cert_list_size; i++) {
		X509 *cert = sk_X509_value(cert_list, i);
		char cert_pin[PINLEN] = { 0 };

		if (get_oob_key_pin(cert, cert_pin, sizeof(cert_pin)) != kr_ok()) {
			return kr_error(EINVAL);
		}

		DEBUG_MSG("[tls_client] received pin  : %s\n", cert_pin);
		for (size_t i = 0; i < params->pins.len; ++i) {
			const char *pin = params->pins.at[i];
			bool match = (strcmp(cert_pin, pin) == 0);
			DEBUG_MSG("[tls_client] configured pin: %s matches? %s\n",
				  pin, match ? "yes" : "no");
			if (match) {
				return ssl_verify_ok;
			}
		}
	}

	/* pins were set, but no one was not matched */
	kr_log_error("[tls_client] certificate PIN check failed\n");

skip_pins:

	if (params->ca_files.len == 0) {
		DEBUG_MSG("[tls_client] empty CA files list\n");
		return ssl_verify_invalid;
	}

	if (params->hostnames.len == 0) {
		DEBUG_MSG("[tls_client] empty hostname list\n");
		return ssl_verify_invalid;
	}

	int ret;
	unsigned int status;
	X509_VERIFY_PARAM *verify_params = SSL_get0_param(tls_session);

	for (size_t i = 0; i < params->hostnames.len; ++i) {
		X509_VERIFY_PARAM_add1_host(verify_params, params->hostnames.at[i],
			strlen(params->hostnames.at[i]));
	}

	int res = SSL_get_verify_result(tls_session);
	if (res == X509_V_OK) {
		return ssl_verify_ok;
	} else {
		kr_log_error("[tls_client] failed to verify peer certificate: "
					"%d\n", res);
		/* return ssl_verify_invalid; */
	}

	return ssl_verify_invalid;
}

struct tls_client_ctx_t *tls_client_ctx_new(const struct tls_client_paramlist_entry *entry,
					    struct worker_ctx *worker)
{
	struct tls_client_ctx_t *ctx = calloc(1, sizeof (struct tls_client_ctx_t));
	if (!ctx) {
		return NULL;
	}

	ctx->c.tls_session = SSL_new(worker->engine->net.ssl_ctx);

	if (ctx->c.tls_session == NULL) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	SSL_set_connect_state(ctx->c.tls_session);

	if (kres_tls_set_priority(ctx->c.tls_session) != kr_ok()) {
		tls_client_ctx_free(ctx);
		return NULL;
	}

	if (!SSL_set1_chain(ctx->c.tls_session, entry->tls_cert_chain)) {
		kr_log_error("[tls_client] failed to set certificate chain\n");
		tls_client_ctx_free(ctx);
		return NULL;
	}

	if (!SSL_use_certificate(ctx->c.tls_session, sk_X509_value(entry->tls_cert_chain, sk_X509_num(entry->tls_cert_chain)-1))) {
		kr_log_error("[tls_client] failed to set leaf certificate\n");
		tls_client_ctx_free(ctx);
		return NULL;
	}

	if (!SSL_use_PrivateKey(ctx->c.tls_session, entry->tls_key)) {
		kr_log_error("[tls_client] failed to set private key\n");
		tls_client_ctx_free(ctx);
		return NULL;
	}

	ctx->c.worker = worker;
	ctx->c.client_side = true;

	ctx->c.read_bio = BIO_new(BIO_s_mem());
	ctx->c.write_bio = BIO_new(BIO_s_mem());
	BIO_set_nbio(ctx->c.read_bio, 1);
	BIO_set_nbio(ctx->c.write_bio, 1);
	SSL_set_bio(ctx->c.tls_session, ctx->c.read_bio, ctx->c.write_bio);

	return ctx;
}

void tls_client_ctx_free(struct tls_client_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->c.tls_session != NULL) {
		SSL_free(ctx->c.tls_session);
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

	session->tls_client_ctx = client_ctx;
	SSL_set_timeout(SSL_get_session(ctx->tls_session), KR_CONN_RTT_MAX * 3);
	ctx->handshake_cb = handshake_cb;
	ctx->handshake_state = TLS_HS_IN_PROGRESS;
	ctx->session = session;

	struct tls_client_paramlist_entry *tls_params = client_ctx->params;
	if (tls_params->session_data != NULL) {
		SSL_set_session(ctx->tls_session, tls_params->session_data);
	}

	while (ctx->handshake_state <= TLS_HS_IN_PROGRESS) {
		/* Don't pass the handshake callback as the connection isn't registered yet. */
		int ret = tls_handshake(ctx, NULL);
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
