/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 * Copyright (C) CZ.NIC, z.s.p.o
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
#include <stdalign.h>
#include <stdlib.h>

#include "contrib/ucw/lib.h"
#include "contrib/base64.h"
#include "daemon/tls.h"
#include "daemon/worker.h"
#include "daemon/session2.h"

#define EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE (60*60*24*7)
#define GNUTLS_PIN_MIN_VERSION  0x030400
#define UNWRAP_BUF_SIZE 131072
#define TLS_CHUNK_SIZE (16 * 1024)

#define VERBOSE_MSG(cl_side, ...)\
	if (cl_side) \
		kr_log_debug(TLSCLIENT, __VA_ARGS__); \
	else \
		kr_log_debug(TLS, __VA_ARGS__);

static const gnutls_datum_t tls_grp_alpn[PROTOLAYER_GRP_COUNT] = {
	[PROTOLAYER_GRP_DOTLS] = { (uint8_t *)"dot", 3 },
	[PROTOLAYER_GRP_DOHTTPS] = { (uint8_t *)"h2", 2 },
};

typedef enum tls_client_hs_state {
	TLS_HS_NOT_STARTED = 0,
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_CLOSING,
	TLS_HS_LAST
} tls_hs_state_t;

struct pl_tls_sess_data {
	struct protolayer_data h;
	bool client_side;
	bool first_handshake_done;
	gnutls_session_t tls_session;
	tls_hs_state_t handshake_state;
	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;
	struct wire_buf unwrap_buf;
	size_t write_queue_size;
	union {
		struct tls_credentials *server_credentials;
		tls_client_param_t *client_params; /**< Ref-counted. */
	};
};


struct tls_credentials * tls_get_ephemeral_credentials(void);
void tls_credentials_log_pins(struct tls_credentials *tls_credentials);
static int client_verify_certificate(gnutls_session_t tls_session);
static struct tls_credentials *tls_credentials_reserve(struct tls_credentials *tls_credentials);

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
	struct pl_tls_sess_data *tls = h;
	if (kr_fails_assert(tls)) {
		errno = EFAULT;
		return -1;
	}

	bool avail = protolayer_queue_has_payload(&tls->unwrap_queue);
	VERBOSE_MSG(tls->client_side, "pull wanted: %zu avail: %s\n",
			len, avail ? "yes" : "no");
	if (!avail) {
		errno = EAGAIN;
		return -1;
	}

	char *dest = buf;
	size_t transfer = 0;
	while (queue_len(tls->unwrap_queue) > 0 && len > 0) {
		struct protolayer_iter_ctx *ctx = queue_head(tls->unwrap_queue);
		struct protolayer_payload *pld = &ctx->payload;

		bool fully_consumed = false;
		if (pld->type == PROTOLAYER_PAYLOAD_BUFFER) {
			size_t to_copy = MIN(len, pld->buffer.len);

			memcpy(dest, pld->buffer.buf, to_copy);
			dest += to_copy;
			len -= to_copy;
			pld->buffer.buf = (char *)pld->buffer.buf + to_copy;
			pld->buffer.len -= to_copy;
			transfer += to_copy;

			if (pld->buffer.len == 0)
				fully_consumed = true;
		} else if (pld->type == PROTOLAYER_PAYLOAD_IOVEC) {
			while (pld->iovec.cnt && len > 0) {
				struct iovec *iov = pld->iovec.iov;
				size_t to_copy = MIN(len, iov->iov_len);

				memcpy(dest, iov->iov_base, to_copy);
				dest += to_copy;
				len -= to_copy;
				iov->iov_base = ((char *)iov->iov_base) + to_copy;
				iov->iov_len -= to_copy;
				transfer += to_copy;

				if (iov->iov_len == 0) {
					pld->iovec.iov++;
					pld->iovec.cnt--;
				}
			}

			if (pld->iovec.cnt == 0)
				fully_consumed = true;
		} else if (pld->type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
			size_t wbl = wire_buf_data_length(pld->wire_buf);
			size_t to_copy = MIN(len, wbl);
			memcpy(dest, wire_buf_data(pld->wire_buf), to_copy);
			dest += to_copy;
			len -= to_copy;
			transfer += to_copy;

			wire_buf_trim(pld->wire_buf, to_copy);
			if (wire_buf_data_length(pld->wire_buf) == 0) {
				wire_buf_reset(pld->wire_buf);
				fully_consumed = true;
			}
		} else if (!pld->type) {
			fully_consumed = true;
		} else {
			kr_assert(false && "Unsupported payload type");
			errno = EFAULT;
			return -1;
		}

		if (!fully_consumed) /* `len` was smaller than the sum of payloads */
			break;

		if (queue_len(tls->unwrap_queue) > 1) {
			/* Finalize queued contexts, except for the last one. */
			protolayer_break(ctx, kr_ok());
			queue_pop(tls->unwrap_queue);
		} else {
			/* The last queued context will `continue` on the next
			 * `gnutls_record_recv`. */
			ctx->payload.type = PROTOLAYER_PAYLOAD_NULL;
			break;
		}
	}

	VERBOSE_MSG(tls->client_side, "pull transfer: %zu\n", transfer);
	return transfer;
}

struct kres_gnutls_push_ctx {
	struct pl_tls_sess_data *sess_data;
	struct iovec iov[];
};

static void kres_gnutls_push_finished(int status, struct session2 *session,
                                      const struct comm_info *comm, void *baton)
{
	struct kres_gnutls_push_ctx *push_ctx = baton;
	struct pl_tls_sess_data *tls = push_ctx->sess_data;
	while (queue_len(tls->wrap_queue)) {
		struct protolayer_iter_ctx *ctx = queue_head(tls->wrap_queue);
		protolayer_break(ctx, kr_ok());
		queue_pop(tls->wrap_queue);
	}
	free(push_ctx);
}

static ssize_t kres_gnutls_vec_push(gnutls_transport_ptr_t h, const giovec_t * iov, int iovcnt)
{
	struct pl_tls_sess_data *tls = h;
	if (kr_fails_assert(tls)) {
		errno = EFAULT;
		return -1;
	}

	if (iovcnt == 0) {
		return 0;
	}

	size_t total_len = 0;
	for (int i = 0; i < iovcnt; i++)
		total_len += iov[i].iov_len;

	struct kres_gnutls_push_ctx *push_ctx =
		malloc(sizeof(*push_ctx) + sizeof(struct iovec[iovcnt]));
	kr_require(push_ctx);
	push_ctx->sess_data = tls;
	memcpy(push_ctx->iov, iov, sizeof(struct iovec[iovcnt]));

	session2_wrap_after(tls->h.session, PROTOLAYER_PROTOCOL_TLS,
			protolayer_iovec(push_ctx->iov, iovcnt), NULL,
			kres_gnutls_push_finished, push_ctx);

	return total_len;
}

static void tls_handshake_success(struct pl_tls_sess_data *tls,
                                  struct session2 *session)
{
	if (tls->client_side) {
		tls_client_param_t *tls_params = tls->client_params;
		gnutls_session_t tls_session = tls->tls_session;
		if (gnutls_session_is_resumed(tls_session) != 0) {
			kr_log_debug(TLSCLIENT, "TLS session has resumed\n");
		} else {
			kr_log_debug(TLSCLIENT, "TLS session has not resumed\n");
			/* session wasn't resumed, delete old session data ... */
			if (tls_params->session_data.data != NULL) {
				gnutls_free(tls_params->session_data.data);
				tls_params->session_data.data = NULL;
				tls_params->session_data.size = 0;
			}
			/* ... and get the new session data */
			gnutls_datum_t tls_session_data = { NULL, 0 };
			int ret = gnutls_session_get_data2(tls_session, &tls_session_data);
			if (ret == 0) {
				tls_params->session_data = tls_session_data;
			}
		}
	}
	if (!tls->first_handshake_done) {
		session2_event_after(session, PROTOLAYER_PROTOCOL_TLS,
				PROTOLAYER_EVENT_CONNECT, NULL);
		tls->first_handshake_done = true;
	}
}

/** Perform TLS handshake and handle error codes according to the documentation.
  * See See https://gnutls.org/manual/html_node/TLS-handshake.html#TLS-handshake
  * The function returns kr_ok() or success or non fatal error, kr_error(EAGAIN) on blocking, or kr_error(EIO) on fatal error.
  */
static int tls_handshake(struct pl_tls_sess_data *tls, struct session2 *session)
{
	int err = gnutls_handshake(tls->tls_session);
	if (err == GNUTLS_E_SUCCESS) {
		/* Handshake finished, return success */
		tls->handshake_state = TLS_HS_DONE;
		struct sockaddr *peer = session2_get_peer(session);
		VERBOSE_MSG(tls->client_side, "TLS handshake with %s has completed\n",
				kr_straddr(peer));
		tls_handshake_success(tls, session);
	} else if (err == GNUTLS_E_AGAIN) {
		return kr_error(EAGAIN);
	} else if (gnutls_error_is_fatal(err)) {
		/* Fatal errors, return error as it's not recoverable */
		VERBOSE_MSG(tls->client_side, "gnutls_handshake failed: %s (%d)\n",
				gnutls_strerror_name(err), err);
		/* Notify the peer about handshake failure via an alert. */
		gnutls_alert_send_appropriate(tls->tls_session, err);
		session2_event(session, PROTOLAYER_EVENT_CONNECT_FAIL,
				(void *)KR_SELECTION_TLS_HANDSHAKE_FAILED);
		return kr_error(EIO);
	} else if (err == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		/* Handle warning when in verbose mode */
		const char *alert_name = gnutls_alert_get_name(gnutls_alert_get(tls->tls_session));
		if (alert_name != NULL) {
			struct sockaddr *peer = session2_get_peer(session);
			VERBOSE_MSG(tls->client_side, "TLS alert from %s received: %s\n",
					kr_straddr(peer), alert_name);
		}
	}
	return kr_ok();
}


/*! Close a TLS context (call gnutls_bye()) */
static void tls_close(struct pl_tls_sess_data *tls, struct session2 *session, bool allow_bye)
{
	if (tls == NULL || tls->tls_session == NULL || kr_fails_assert(session))
		return;

	/* Store the current session data for potential resumption of this session */
	if (session->outgoing && tls->client_params) {
		gnutls_free(tls->client_params->session_data.data);
		tls->client_params->session_data.data = NULL;
		tls->client_params->session_data.size = 0;
		gnutls_session_get_data2(
				tls->tls_session,
				&tls->client_params->session_data);
	}

	const struct sockaddr *peer = session2_get_peer(session);
	if (allow_bye && tls->handshake_state == TLS_HS_DONE) {
		VERBOSE_MSG(tls->client_side, "closing tls connection to `%s`\n",
			       kr_straddr(peer));
		tls->handshake_state = TLS_HS_CLOSING;
		gnutls_bye(tls->tls_session, GNUTLS_SHUT_RDWR);
	} else {
		VERBOSE_MSG(tls->client_side, "closing tls connection to `%s` (without bye)\n",
			       kr_straddr(peer));
	}
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
	/* TODO: simplify this function by using gnutls_x509_crt_get_key_id() */
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

/*! Log DNS-over-TLS OOB key-pin form of current credentials:
 * https://tools.ietf.org/html/rfc7858#appendix-A */
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
	kr_log_debug(TLS, "could not calculate RFC 7858 OOB key-pin; GnuTLS 3.4.0+ required\n");
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

int tls_certificate_set(const char *tls_cert, const char *tls_key)
{
	if (kr_fails_assert(the_network)) {
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
	struct tls_credentials *old_credentials = the_network->tls_credentials;

	/* Start using the new x509_credentials */
	the_network->tls_credentials = tls_credentials;
	tls_credentials_log_pins(the_network->tls_credentials);

	if (old_credentials) {
		err = tls_credentials_release(old_credentials);
		if (err != kr_error(EBUSY)) {
			return err;
		}
	}

	return kr_ok();
}

/*! Borrow TLS credentials for context. */
static struct tls_credentials *tls_credentials_reserve(struct tls_credentials *tls_credentials)
{
	if (!tls_credentials) {
		return NULL;
	}
	tls_credentials->count++;
	return tls_credentials;
}

/*! Release TLS credentials for context (decrements refcount or frees). */
int tls_credentials_release(struct tls_credentials *tls_credentials)
{
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

/*! Free TLS credentials, must not be called if it holds positive refcount. */
void tls_credentials_free(struct tls_credentials *tls_credentials)
{
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

	VERBOSE_MSG(true, "freeing TLS parameters %p\n", (void *)entry);

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

tls_client_param_t * tls_client_param_new(void)
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
static bool construct_key(const union kr_sockaddr *addr, uint32_t *len, char *key)
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

tls_client_param_t **tls_client_param_getptr(tls_client_params_t **params,
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
	const union kr_sockaddr *ia = (const union kr_sockaddr *)addr;
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
	const union kr_sockaddr *ia = (const union kr_sockaddr *)addr;
	char key[sizeof(ia->ip6.sin6_port) + sizeof(ia->ip6.sin6_addr)];
	uint32_t len;
	if (!construct_key(ia, &len, key))
		return kr_error(EINVAL);
	trie_val_t param_ptr;
	int ret = trie_del(params, key, len, &param_ptr);
	if (ret != KNOT_EOK)
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
		if (kr_log_is_debug(TLS, NULL)) {
			char pin_base64[TLS_SHA256_BASE64_BUFLEN];
			/* DEBUG: additionally compute and print the base64 pin.
			 * Not very efficient, but that's OK for DEBUG. */
			ret = get_oob_key_pin(cert, pin_base64, sizeof(pin_base64), false);
			if (ret == GNUTLS_E_SUCCESS) {
				VERBOSE_MSG(true, "received pin: %s\n", pin_base64);
			} else {
				VERBOSE_MSG(true, "failed to convert received pin\n");
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
			VERBOSE_MSG(true, "matched a configured pin no. %zd\n", j);
			return GNUTLS_E_SUCCESS;
		}
		VERBOSE_MSG(true, "none of %zd configured pin(s) matched\n",
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
	struct pl_tls_sess_data *tls = gnutls_session_get_ptr(tls_session);
	if (kr_fails_assert(tls->client_params))
		return GNUTLS_E_CERTIFICATE_ERROR;

	if (tls->client_params->insecure) {
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

	if (tls->client_params->pins.len > 0)
		/* check hash of the certificate but ignore everything else */
		return client_verify_pin(cert_list_size, cert_list, tls->client_params);
	else
		return client_verify_certchain(tls->tls_session, tls->client_params->hostname);
}

static int tls_pull_timeout_func(gnutls_transport_ptr_t h, unsigned int ms)
{
	struct pl_tls_sess_data *tls = h;
	if (kr_fails_assert(tls)) {
		errno = EFAULT;
		return -1;
	}

	size_t avail = protolayer_queue_count_payload(&tls->unwrap_queue);
	VERBOSE_MSG(tls->client_side, "timeout check: available: %zu\n", avail);
	if (!avail) {
		errno = EAGAIN;
		return -1;
	}
	return avail;
}

static int pl_tls_sess_data_deinit(struct pl_tls_sess_data *tls)
{
	if (tls->tls_session) {
		/* Don't terminate TLS connection, just tear it down */
		gnutls_deinit(tls->tls_session);
		tls->tls_session = NULL;
	}

	if (tls->client_side) {
		tls_client_param_unref(tls->client_params);
	} else {
		tls_credentials_release(tls->server_credentials);
	}
	wire_buf_deinit(&tls->unwrap_buf);
	queue_deinit(tls->unwrap_queue); /* TODO: break contexts? */
	return kr_ok();
}

static int pl_tls_sess_server_init(struct protolayer_manager *manager,
                                   struct pl_tls_sess_data *tls)
{
	if (kr_fails_assert(the_worker && the_engine))
		return kr_error(EINVAL);

	if (!the_network->tls_credentials) {
		the_network->tls_credentials = tls_get_ephemeral_credentials();
		if (!the_network->tls_credentials) {
			kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
			return kr_error(EINVAL);
		}
		kr_log_info(TLS, "Using ephemeral TLS credentials\n");
		tls_credentials_log_pins(the_network->tls_credentials);
	}

	time_t now = time(NULL);
	if (the_network->tls_credentials->valid_until != GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION) {
		if (the_network->tls_credentials->ephemeral_servicename) {
			/* ephemeral cert: refresh if due to expire within a week */
			if (now >= the_network->tls_credentials->valid_until - EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE) {
				struct tls_credentials *newcreds = tls_get_ephemeral_credentials();
				if (newcreds) {
					tls_credentials_release(the_network->tls_credentials);
					the_network->tls_credentials = newcreds;
					kr_log_info(TLS, "Renewed expiring ephemeral X.509 cert\n");
				} else {
					kr_log_error(TLS, "Failed to renew expiring ephemeral X.509 cert, using existing one\n");
				}
			}
		} else {
			/* non-ephemeral cert: warn once when certificate expires */
			if (now >= the_network->tls_credentials->valid_until) {
				kr_log_error(TLS, "X.509 certificate has expired!\n");
				the_network->tls_credentials->valid_until = GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
			}
		}
	}

	int flags = GNUTLS_SERVER | GNUTLS_NONBLOCK;
#if GNUTLS_VERSION_NUMBER >= 0x030705
	if (gnutls_check_version("3.7.5"))
		flags |= GNUTLS_NO_TICKETS_TLS12;
#endif
	int ret = gnutls_init(&tls->tls_session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_init(): %s (%d)\n", gnutls_strerror_name(ret), ret);
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	tls->server_credentials = tls_credentials_reserve(the_network->tls_credentials);
	ret = gnutls_credentials_set(tls->tls_session, GNUTLS_CRD_CERTIFICATE,
				     tls->server_credentials->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_credentials_set(): %s (%d)\n", gnutls_strerror_name(ret), ret);
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	ret = kres_gnutls_set_priority(tls->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	tls->client_side = false;
	wire_buf_init(&tls->unwrap_buf, UNWRAP_BUF_SIZE);

	gnutls_transport_set_pull_function(tls->tls_session, kres_gnutls_pull);
	gnutls_transport_set_vec_push_function(tls->tls_session, kres_gnutls_vec_push);
	gnutls_transport_set_ptr(tls->tls_session, tls);

	if (the_network->tls_session_ticket_ctx) {
		tls_session_ticket_enable(the_network->tls_session_ticket_ctx,
					  tls->tls_session);
	}

	const gnutls_datum_t *alpn = &tls_grp_alpn[manager->grp];
	if (alpn->size) { /* ALPN is a non-empty string */
		flags = 0;
#if GNUTLS_VERSION_NUMBER >= 0x030500
		/* Mandatory ALPN means the protocol must match if and
		 * only if ALPN extension is used by the client. */
		flags |= GNUTLS_ALPN_MANDATORY;
#endif

		ret = gnutls_alpn_set_protocols(tls->tls_session, alpn, 1, flags);
		if (ret != GNUTLS_E_SUCCESS) {
			kr_log_error(TLS, "gnutls_alpn_set_protocols(): %s (%d)\n", gnutls_strerror_name(ret), ret);
			pl_tls_sess_data_deinit(tls);
			return ret;
		}
	}

	return kr_ok();
}

static int pl_tls_sess_client_init(struct protolayer_manager *manager,
                                   struct pl_tls_sess_data *tls,
                                   tls_client_param_t *param)
{
	unsigned int flags = GNUTLS_CLIENT | GNUTLS_NONBLOCK
#ifdef GNUTLS_ENABLE_FALSE_START
			     | GNUTLS_ENABLE_FALSE_START
#endif
	;
#if GNUTLS_VERSION_NUMBER >= 0x030705
	if (gnutls_check_version("3.7.5"))
		flags |= GNUTLS_NO_TICKETS_TLS12;
#endif
	int ret = gnutls_init(&tls->tls_session,  flags);
	if (ret != GNUTLS_E_SUCCESS) {
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	ret = kres_gnutls_set_priority(tls->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	/* Must take a reference on parameters as the credentials are owned by it
	 * and must not be freed while the session is active. */
	++(param->refs);
	tls->client_params = param;

	ret = gnutls_credentials_set(tls->tls_session, GNUTLS_CRD_CERTIFICATE,
	                             param->credentials);
	if (ret == GNUTLS_E_SUCCESS && param->hostname) {
		ret = gnutls_server_name_set(tls->tls_session, GNUTLS_NAME_DNS,
					param->hostname, strlen(param->hostname));
		kr_log_debug(TLSCLIENT, "set hostname, ret = %d\n", ret);
	} else if (!param->hostname) {
		kr_log_debug(TLSCLIENT, "no hostname\n");
	}

	if (ret != GNUTLS_E_SUCCESS) {
		pl_tls_sess_data_deinit(tls);
		return ret;
	}

	tls->client_side = true;
	wire_buf_init(&tls->unwrap_buf, UNWRAP_BUF_SIZE);

	gnutls_transport_set_pull_function(tls->tls_session, kres_gnutls_pull);
	gnutls_transport_set_vec_push_function(tls->tls_session, kres_gnutls_vec_push);
	gnutls_transport_set_ptr(tls->tls_session, tls);

	return kr_ok();
}

static int pl_tls_sess_init(struct protolayer_manager *manager,
                            void *sess_data,
                            void *param)
{
	struct pl_tls_sess_data *tls = sess_data;
	manager->session->secure = true;
	queue_init(tls->unwrap_queue);
	queue_init(tls->wrap_queue);
	if (manager->session->outgoing)
		return pl_tls_sess_client_init(manager, tls, param);
	else
		return pl_tls_sess_server_init(manager, tls);
}

static int pl_tls_sess_deinit(struct protolayer_manager *manager,
                              void *sess_data)
{
	return pl_tls_sess_data_deinit(sess_data);
}

static enum protolayer_iter_cb_result pl_tls_unwrap(void *sess_data, void *iter_data,
                                               struct protolayer_iter_ctx *ctx)
{
	int brstatus = kr_ok();
	struct pl_tls_sess_data *tls = sess_data;
	struct session2 *s = ctx->manager->session;

	queue_push(tls->unwrap_queue, ctx);

	/* Ensure TLS handshake is performed before receiving data.
	 * See https://www.gnutls.org/manual/html_node/TLS-handshake.html */
	while (tls->handshake_state <= TLS_HS_IN_PROGRESS) {
		int err = tls_handshake(tls, s);
		if (err == kr_error(EAGAIN)) {
			return protolayer_async(); /* Wait for more data */
		} else if (err != kr_ok()) {
			brstatus = err;
			goto exit_break;
		}
	}

	/* See https://gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination */
	while (true) {
		ssize_t count = gnutls_record_recv(tls->tls_session,
				wire_buf_free_space(&tls->unwrap_buf),
				wire_buf_free_space_length(&tls->unwrap_buf));
		if (count == GNUTLS_E_AGAIN) {
			if (!protolayer_queue_has_payload(&tls->unwrap_queue)) {
				/* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
				break;
			}
			continue;
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue;
		} else if (count == GNUTLS_E_REHANDSHAKE) {
			/* See https://www.gnutls.org/manual/html_node/Re_002dauthentication.html */
			struct sockaddr *peer = session2_get_peer(s);
			VERBOSE_MSG(tls->client_side, "TLS rehandshake with %s has started\n",
					kr_straddr(peer));
			tls->handshake_state = TLS_HS_IN_PROGRESS;
			int err = kr_ok();
			while (tls->handshake_state <= TLS_HS_IN_PROGRESS) {
				err = tls_handshake(tls, s);
				if (err == kr_error(EAGAIN)) {
					break;
				} else if (err != kr_ok()) {
					brstatus = err;
					goto exit_break;
				}
			}
			if (err == kr_error(EAGAIN)) {
				/* pull function is out of data */
				break;
			}
			/* There are can be data available, check it. */
			continue;
		} else if (count < 0) {
			VERBOSE_MSG(tls->client_side, "gnutls_record_recv failed: %s (%zd)\n",
					gnutls_strerror_name(count), count);
			brstatus = kr_error(EIO);
			goto exit_break;
		} else if (count == 0) {
			break;
		}
		VERBOSE_MSG(tls->client_side, "received %zd data\n", count);
		wire_buf_consume(&tls->unwrap_buf, count);
		if (wire_buf_free_space_length(&tls->unwrap_buf) == 0 && protolayer_queue_has_payload(&tls->unwrap_queue) > 0) {
			/* wire buffer is full but not all data was consumed */
			brstatus = kr_error(ENOSPC);
			goto exit_break;
		}

		if (kr_fails_assert(queue_len(tls->unwrap_queue) == 1)) {
			brstatus = kr_error(EINVAL);
			goto exit_break;
		}

		struct protolayer_iter_ctx *ctx_head = queue_head(tls->unwrap_queue);
		if (kr_fails_assert(ctx == ctx_head)) {
			protolayer_break(ctx, kr_error(EINVAL));
			ctx = ctx_head;
		}
	}

	/* Here all data must be consumed. */
	if (protolayer_queue_has_payload(&tls->unwrap_queue)) {
		/* Something went wrong, better return error.
		 * This is most probably due to gnutls_record_recv() did not
		 * consume all available network data by calling kres_gnutls_pull().
		 * TODO assess the need for buffering of data amount.
		 */
		brstatus = kr_error(ENOSPC);
		goto exit_break;
	}

	struct protolayer_iter_ctx *ctx_head = queue_head(tls->unwrap_queue);
	if (!kr_fails_assert(ctx == ctx_head))
		queue_pop(tls->unwrap_queue);
	ctx->payload = protolayer_wire_buf(&tls->unwrap_buf);
	return protolayer_continue(ctx);

exit_break:
	ctx_head = queue_head(tls->unwrap_queue);
	if (!kr_fails_assert(ctx == ctx_head))
		queue_pop(tls->unwrap_queue);
	return protolayer_break(ctx, brstatus);
}

static ssize_t pl_tls_submit(gnutls_session_t tls_session,
                             struct protolayer_payload payload)
{
	if (payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF)
		payload = protolayer_as_buffer(&payload);

	if (payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		ssize_t count = gnutls_record_send(tls_session,
				payload.buffer.buf, payload.buffer.len);
		if (count < 0)
			return count;

		return payload.buffer.len;
	} else if (payload.type == PROTOLAYER_PAYLOAD_IOVEC) {
		ssize_t total_submitted = 0;
		for (int i = 0; i < payload.iovec.cnt; i++) {
			struct iovec iov = payload.iovec.iov[i];
			ssize_t count = gnutls_record_send(tls_session,
					iov.iov_base, iov.iov_len);
			if (count < 0)
				return count;

			total_submitted += iov.iov_len;
		}
		return total_submitted;
	}

	kr_assert(false && "Invalid payload");
	return kr_error(EINVAL);
}

static enum protolayer_iter_cb_result pl_tls_wrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	struct pl_tls_sess_data *tls = sess_data;
	gnutls_session_t tls_session = tls->tls_session;

	gnutls_record_cork(tls_session);

	ssize_t submitted = pl_tls_submit(tls_session, ctx->payload);
	if (submitted < 0) {
		VERBOSE_MSG(tls->client_side, "pl_tls_submit failed: %s (%zd)\n",
				gnutls_strerror_name(submitted), submitted);
		return protolayer_break(ctx, submitted);
	}
	queue_push(tls->wrap_queue, ctx);

	int ret = gnutls_record_uncork(tls_session, GNUTLS_RECORD_WAIT);
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret)) {
			queue_pop(tls->wrap_queue);
			return protolayer_break(ctx, kr_error(EAGAIN));
		} else {
			queue_pop(tls->wrap_queue);
			VERBOSE_MSG(tls->client_side, "gnutls_record_uncork failed: %s (%d)\n",
					gnutls_strerror_name(ret), ret);
			return protolayer_break(ctx, kr_error(EIO));
		}
	}

	if (ret != submitted) {
		kr_log_error(TLS, "gnutls_record_uncork didn't send all data (%d of %zd)\n", ret, submitted);
		return protolayer_break(ctx, kr_error(EIO));
	}

	return protolayer_async();
}

static enum protolayer_event_cb_result pl_tls_client_connect_start(
		struct pl_tls_sess_data *tls, struct session2 *session)
{
	if (tls->handshake_state != TLS_HS_NOT_STARTED)
		return PROTOLAYER_EVENT_CONSUME;

	if (kr_fails_assert(session->outgoing))
		return PROTOLAYER_EVENT_CONSUME;

	gnutls_session_set_ptr(tls->tls_session, tls);
	gnutls_handshake_set_timeout(tls->tls_session, the_network->tcp.tls_handshake_timeout);
	gnutls_transport_set_pull_timeout_function(tls->tls_session, tls_pull_timeout_func);
	tls->handshake_state = TLS_HS_IN_PROGRESS;

	tls_client_param_t *tls_params = tls->client_params;
	if (tls_params->session_data.data != NULL) {
		gnutls_session_set_data(tls->tls_session, tls_params->session_data.data,
				tls_params->session_data.size);
	}

	/* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
	while (tls->handshake_state <= TLS_HS_IN_PROGRESS) {
		int ret = tls_handshake(tls, session);
		if (ret != kr_ok()) {
			if (ret == kr_error(EAGAIN)) {
				session2_timer_stop(session);
				session2_timer_start(session,
						PROTOLAYER_EVENT_GENERAL_TIMEOUT,
						MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
			}
			return PROTOLAYER_EVENT_CONSUME;
		}
	}

	return PROTOLAYER_EVENT_CONSUME;
}

static enum protolayer_event_cb_result pl_tls_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct protolayer_manager *manager, void *sess_data)
{
	struct session2 *s = manager->session;
	struct pl_tls_sess_data *tls = sess_data;

	if (event == PROTOLAYER_EVENT_CLOSE) {
		tls_close(tls, s, true); /* WITH gnutls_bye */
		return PROTOLAYER_EVENT_PROPAGATE;
	}
	if (event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		tls_close(tls, s, false); /* WITHOUT gnutls_bye */
		return PROTOLAYER_EVENT_PROPAGATE;
	}

	if (tls->client_side) {
		if (event == PROTOLAYER_EVENT_CONNECT)
			return pl_tls_client_connect_start(tls, s);
	} else {
		if (event == PROTOLAYER_EVENT_CONNECT) {
			/* TLS sends its own _CONNECT event when the handshake
			 * is finished. */
			return PROTOLAYER_EVENT_CONSUME;
		}
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_tls_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct protolayer_manager *manager, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_STATS_SEND_ERR) {
		the_worker->stats.err_tls += 1;
		return PROTOLAYER_EVENT_CONSUME;
	} else if (event == PROTOLAYER_EVENT_STATS_QRY_OUT) {
		the_worker->stats.tls += 1;
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static void pl_tls_request_init(struct protolayer_manager *manager,
                                struct kr_request *req,
                                void *sess_data)
{
	req->qsource.comm_flags.tls = true;
}

void tls_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_PROTOCOL_TLS] = (struct protolayer_globals){
		.sess_size = sizeof(struct pl_tls_sess_data),
		.sess_deinit = pl_tls_sess_deinit,
		.wire_buf_overhead = TLS_CHUNK_SIZE,
		.sess_init = pl_tls_sess_init,
		.unwrap = pl_tls_unwrap,
		.wrap = pl_tls_wrap,
		.event_unwrap = pl_tls_event_unwrap,
		.event_wrap = pl_tls_event_wrap,
		.request_init = pl_tls_request_init
	};
}

#undef VERBOSE_MSG
