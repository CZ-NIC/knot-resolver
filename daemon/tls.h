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
#include <gnutls/gnutls.h>
#include <libknot/packet/pkt.h>
#include "lib/defines.h"
#include "lib/generic/array.h"
#include "lib/generic/map.h"

#define MAX_TLS_PADDING KR_EDNS_PAYLOAD
#define TLS_MAX_UNCORK_RETRIES 100

struct tls_ctx_t;
struct tls_client_ctx_t;
struct tls_credentials {
	int count;
	char *tls_cert;
	char *tls_key;
	gnutls_certificate_credentials_t credentials;
	time_t valid_until;
	char *ephemeral_servicename;
};

struct tls_client_paramlist_entry {
	array_t(const char *) ca_files;
	array_t(const char *) hostnames;
	array_t(const char *) pins;
	gnutls_certificate_credentials_t credentials;
	gnutls_datum_t session_data;
};

struct worker_ctx;
struct qr_task;

typedef enum tls_client_hs_state {
	TLS_HS_NOT_STARTED = 0,
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_CLOSING,
	TLS_HS_LAST
} tls_hs_state_t;

typedef int (*tls_handshake_cb) (struct session *session, int status);

typedef enum tls_client_param {
	TLS_CLIENT_PARAM_NONE = 0,
	TLS_CLIENT_PARAM_PIN,
	TLS_CLIENT_PARAM_HOSTNAME,
	TLS_CLIENT_PARAM_CA,
} tls_client_param_t;

struct tls_common_ctx {
	bool client_side;
	gnutls_session_t tls_session;
	tls_hs_state_t handshake_state;
	struct session *session;
	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[4096];
	tls_handshake_cb handshake_cb;
	struct worker_ctx *worker;
	struct qr_task *task;
};

struct tls_ctx_t {
	/*
	 * Since pointer to tls_ctx_t needs to be casted
	 * to  tls_ctx_common in some functions,
	 * this field must be always at first position
	 */
	struct tls_common_ctx c;
	struct tls_credentials *credentials;
};

struct tls_client_ctx_t {
	/*
	 * Since pointer to tls_client_ctx_t needs to be casted
	 * to  tls_ctx_common in some functions,
	 * this field must be always at first position
	 */
	struct tls_common_ctx c;
	struct tls_client_paramlist_entry *params;
};

/*! Create an empty TLS context in query context */
struct tls_ctx_t* tls_new(struct worker_ctx *worker);

/*! Close a TLS context (call gnutls_bye()) */
void tls_close(struct tls_common_ctx *ctx);

/*! Release a TLS context */
void tls_free(struct tls_ctx_t* tls);

/*! Push new data to TLS context for sending */
int tls_push(struct qr_task *task, uv_handle_t* handle, knot_pkt_t * pkt);

/*! Unwrap incoming data from a TLS stream and pass them to TCP session.
 * @return the number of newly-completed requests (>=0) or an error code
 */
int tls_process(struct worker_ctx *worker, uv_stream_t *handle, const uint8_t *buf, ssize_t nread);

/*! Set TLS certificate and key from files. */
int tls_certificate_set(struct network *net, const char *tls_cert, const char *tls_key);

/*! Borrow TLS credentials for context. */
struct tls_credentials *tls_credentials_reserve(struct tls_credentials *tls_credentials);

/*! Release TLS credentials for context (decrements refcount or frees). */
int tls_credentials_release(struct tls_credentials *tls_credentials);

/*! Free TLS credentials, must not be called if it holds positive refcount. */
void tls_credentials_free(struct tls_credentials *tls_credentials);

/*! Log DNS-over-TLS OOB key-pin form of current credentials:
 * https://tools.ietf.org/html/rfc7858#appendix-A */
void tls_credentials_log_pins(struct tls_credentials *tls_credentials);

/*! Generate new ephemeral TLS credentials. */
struct tls_credentials * tls_get_ephemeral_credentials(struct engine *engine);

/*! Get TLS handshake state. */
tls_hs_state_t tls_get_hs_state(const struct tls_common_ctx *ctx);

/*! Set TLS handshake state. */
int tls_set_hs_state(struct tls_common_ctx *ctx, tls_hs_state_t state);

/*! Set TLS authentication parameters for given address.
 * Note: hostnames must be imported before ca files,
 *       otherwise ca files will not be imported at all.
 */
int tls_client_params_set(map_t *tls_client_paramlist,
			  const char *addr, uint16_t port,
			  const char *param, tls_client_param_t param_type);

/*! Free TLS authentication parameters. */
int tls_client_params_free(map_t *tls_client_paramlist);

/*! Allocate new client TLS context */
struct tls_client_ctx_t *tls_client_ctx_new(const struct tls_client_paramlist_entry *entry,
					    struct worker_ctx *worker);

/*! Free client TLS context */
void tls_client_ctx_free(struct tls_client_ctx_t *ctx);

int tls_client_connect_start(struct tls_client_ctx_t *client_ctx,
			     struct session *session,
			     tls_handshake_cb handshake_cb);

int tls_client_ctx_set_params(struct tls_client_ctx_t *ctx,
			      struct tls_client_paramlist_entry *entry,
			      struct session *session);


/* Session tickets, server side.  Implementation in ./tls_session_ticket-srv.c */

/*! Opaque struct used by tls_session_ticket_* functions. */
struct tls_session_ticket_ctx;

/*! Suggested maximum reasonable secret length. */
#define TLS_SESSION_TICKET_SECRET_MAX_LEN 1024

/*! Create a session ticket context and initialize it (secret gets copied inside).
 *
 * Passing zero-length secret implies using a random key, i.e. not synchronized
 * between multiple instances.
 *
 * Beware that knowledge of the secret (if nonempty) breaks forward secrecy,
 * so you should rotate the secret regularly and securely erase all past secrets.
 * With TLS < 1.3 it's probably too risky to set nonempty secret.
 */
struct tls_session_ticket_ctx * tls_session_ticket_ctx_create(
		uv_loop_t *loop, const char *secret, size_t secret_len);

/*! Try to enable session tickets for a server session. */
void tls_session_ticket_enable(struct tls_session_ticket_ctx *ctx, gnutls_session_t session);

/*! Free all resources of the session ticket context.  NULL is accepted as well. */
void tls_session_ticket_ctx_destroy(struct tls_session_ticket_ctx *ctx);

