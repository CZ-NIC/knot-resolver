/* Copyright (C) 2016 American Civil Liberties Union (ACLU)
 * Copyright (C) CZ.NIC, z.s.p.o
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <uv.h>
#include <gnutls/gnutls.h>
#include <libknot/packet/pkt.h>
#include "lib/defines.h"
#include "lib/generic/array.h"
#include "lib/generic/trie.h"
#include "lib/utils.h"

#define MAX_TLS_PADDING KR_EDNS_PAYLOAD
#define TLS_MAX_UNCORK_RETRIES 100
#define ENABLE_QUIC

/* rfc 5476, 7.3 - handshake Protocol overview
 * https://tools.ietf.org/html/rfc5246#page-33
 * Message flow for a full handshake (only mandatory messages)
 * ClientHello           -------->
                                        ServerHello
                         <--------      ServerHelloDone
   ClientKeyExchange
   Finished              -------->
                         <--------      Finished
 *
 * See also https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/
 * So it takes 2 RTT.
 * As we use session tickets, there are additional messages, add one RTT mode.
 */
#define TLS_MAX_HANDSHAKE_TIME (KR_CONN_RTT_MAX * (uint64_t)3)

/** Transport session (opaque). */
struct session2;

struct tls_ctx;
struct tls_client_ctx;
struct tls_credentials {
	int count;
	char *tls_cert;
	char *tls_key;
	gnutls_certificate_credentials_t credentials;
	time_t valid_until;
	char *ephemeral_servicename;
#ifdef ENABLE_QUIC
	gnutls_anti_replay_t tls_anti_replay;
	// gnutls_datum_t tls_ticket_key;
#endif /* ENABLE_QUIC */
};


#define TLS_SHA256_RAW_LEN 32 /* gnutls_hash_get_len(GNUTLS_DIG_SHA256) */
/** Required buffer length for pin_sha256, including the zero terminator. */
#define TLS_SHA256_BASE64_BUFLEN (((TLS_SHA256_RAW_LEN * 8 + 4) / 6) + 3 + 1)


/** TLS authentication parameters for a single address-port pair. */
typedef struct {
	uint32_t refs; /**< Reference count; consider TLS sessions in progress. */
	bool insecure; /**< Use no authentication. */
	const char *hostname; /**< Server name for SNI and certificate check, lowercased.  */
	array_t(const char *) ca_files; /**< Paths to certificate files; not really used. */
	array_t(const uint8_t *) pins; /**< Certificate pins as raw unterminated strings.*/
	gnutls_certificate_credentials_t credentials; /**< CA creds. in gnutls format.  */
	gnutls_datum_t session_data; /**< Session-resumption data gets stored here.    */
} tls_client_param_t;
/** Holds configuration for TLS authentication for all potential servers.
 * Special case: NULL pointer also means empty. */
typedef trie_t tls_client_params_t;

/** Get a pointer-to-pointer to TLS auth params.
 * If it didn't exist, it returns NULL (if !do_insert) or pointer to NULL. */
tls_client_param_t **tls_client_param_getptr(tls_client_params_t **params,
		const struct sockaddr *addr, bool do_insert);

/** Get a pointer to TLS auth params or NULL. */
static inline tls_client_param_t *
	tls_client_param_get(tls_client_params_t *params, const struct sockaddr *addr)
{
	tls_client_param_t **pe = tls_client_param_getptr(&params, addr, false);
	return pe ? *pe : NULL;
}

/** Allocate and initialize the structure (with ->ref = 1). */
tls_client_param_t * tls_client_param_new(void);
/** Reference-counted free(); any inside data is freed alongside. */
void tls_client_param_unref(tls_client_param_t *entry);

int tls_client_param_remove(tls_client_params_t *params, const struct sockaddr *addr);
/** Free TLS authentication parameters. */
void tls_client_params_free(tls_client_params_t *params);

/*! Set TLS certificate and key from files. */
int tls_certificate_set(const char *tls_cert, const char *tls_key);

/*! Release TLS credentials for context (decrements refcount or frees). */
int tls_credentials_release(struct tls_credentials *tls_credentials);

/*! Generate new ephemeral TLS credentials. */
struct tls_credentials * tls_get_ephemeral_credentials(void);

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

/*! Free TLS credentials. */
void tls_credentials_free(struct tls_credentials *tls_credentials);

