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

struct tls_ctx_t;
struct tls_credentials;
struct tls_credentials {
	int count;
	char *tls_cert;
	char *tls_key;
	gnutls_certificate_credentials_t credentials;
};

/*! Toggle verbose logging from TLS context. */
void tls_setup_logging(bool verbose);

/*! Create an empty TLS context in query context */
struct tls_ctx_t* tls_new(struct worker_ctx *worker);

/*! Close a TLS context */
void tls_free(struct tls_ctx_t* tls);

/*! Push new data to TLS context for sending */
int tls_push(struct qr_task *task, uv_handle_t* handle, knot_pkt_t * pkt);

/*! Unwrap incoming data from a TLS stream and pass them to TCP session. */
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
