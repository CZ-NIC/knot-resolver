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
};

typedef enum tls_client_hs_state {
	TLS_HS_NOT_STARTED = 0,
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_LAST
} tls_client_hs_state_t;

typedef int (*tls_handshake_cb) (struct session *session, int status);

/*! Create an empty TLS context in query context */
struct tls_ctx_t* tls_new(struct worker_ctx *worker);

/*! Close a TLS context */
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
struct tls_credentials *tls_credentials_reserve(struct tls_credentials *worker);

/*! Release TLS credentials for context (decrements refcount or frees). */
int tls_credentials_release(struct tls_credentials *tls_credentials);

/*! Free TLS credentials, must not be called if it holds positive refcount. */
void tls_credentials_free(struct tls_credentials *tls_credentials);

/*! Log DNS-over-TLS OOB key-pin form of current credentials:
 * https://tools.ietf.org/html/rfc7858#appendix-A */
void tls_credentials_log_pins(struct tls_credentials *tls_credentials);

/*! Generate new ephemeral TLS credentials. */
struct tls_credentials * tls_get_ephemeral_credentials(struct engine *engine);

/*! Set TLS authentication parameters for given address. */
int tls_client_params_set(map_t *tls_client_paramlist,
			  const char *addr, uint16_t port,
			  const char *ca_file, const char *hostname, const char *pin);

/*! Free TLS authentication parameters. */
int tls_client_params_free(map_t *tls_client_paramlist);

/*! Allocate new client TLS context */
struct tls_client_ctx_t *tls_client_ctx_new(const struct tls_client_paramlist_entry *entry);

int tls_client_process(struct worker_ctx *worker, uv_stream_t *handle,
		       const uint8_t *buf, ssize_t nread);

/*! Free client TLS context */
void tls_client_ctx_free(struct tls_client_ctx_t *ctx);

int tls_client_connect_start(struct tls_client_ctx_t *ctx, struct session *session,
			     tls_handshake_cb handshake_cb);

void tls_client_close(struct tls_client_ctx_t *ctx);

int tls_client_push(struct qr_task *task, uv_handle_t *handle, knot_pkt_t *pkt);

tls_client_hs_state_t tls_client_get_hs_state(const struct tls_client_ctx_t *ctx);

int tls_client_set_hs_state(struct tls_client_ctx_t *ctx, tls_client_hs_state_t state);

int tls_client_ctx_set_params(struct tls_client_ctx_t *ctx,
			      const struct tls_client_paramlist_entry *entry);
