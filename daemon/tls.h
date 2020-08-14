/*  Copyright (C) 2016 American Civil Liberties Union (ACLU)
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
 #define TLS_MAX_HANDSHAKE_TIME (KR_CONN_RTT_MAX * 3)

/** Transport session (opaque). */
struct session;

struct tls_ctx;
struct tls_client_ctx;
struct tls_credentials {
	int count;
	char *tls_cert;
	char *tls_key;
	gnutls_certificate_credentials_t credentials;
	time_t valid_until;
	char *ephemeral_servicename;
};


#define TLS_SHA256_RAW_LEN 32 /* gnutls_hash_get_len(GNUTLS_DIG_SHA256) */
/** Required buffer length for pin_sha256, including the zero terminator. */
#define TLS_SHA256_BASE64_BUFLEN (((TLS_SHA256_RAW_LEN * 8 + 4) / 6) + 3 + 1)

#if GNUTLS_VERSION_NUMBER >= 0x030400
	#define TLS_CAN_USE_PINS 1
#else
	#define TLS_CAN_USE_PINS 0
#endif


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
tls_client_param_t ** tls_client_param_getptr(tls_client_params_t **params,
				const struct sockaddr *addr, bool do_insert);

/** Get a pointer to TLS auth params or NULL. */
static inline tls_client_param_t *
	tls_client_param_get(tls_client_params_t *params, const struct sockaddr *addr)
{
	tls_client_param_t **pe = tls_client_param_getptr(&params, addr, false);
	return pe ? *pe : NULL;
}

/** Allocate and initialize the structure (with ->ref = 1). */
tls_client_param_t * tls_client_param_new();
/** Reference-counted free(); any inside data is freed alongside. */
void tls_client_param_unref(tls_client_param_t *entry);

int tls_client_param_remove(tls_client_params_t *params, const struct sockaddr *addr);
/** Free TLS authentication parameters. */
void tls_client_params_free(tls_client_params_t *params);


struct worker_ctx;
struct qr_task;
struct network;
struct engine;

typedef enum tls_client_hs_state {
	TLS_HS_NOT_STARTED = 0,
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_CLOSING,
	TLS_HS_LAST
} tls_hs_state_t;

typedef int (*tls_handshake_cb) (struct session *session, int status);


struct tls_common_ctx {
	bool client_side;
	gnutls_session_t tls_session;
	tls_hs_state_t handshake_state;
	struct session *session;
	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[16384];
	tls_handshake_cb handshake_cb;
	struct worker_ctx *worker;
	size_t write_queue_size;
};

struct tls_ctx {
	/*
	 * Since pointer to tls_ctx needs to be casted
	 * to  tls_ctx_common in some functions,
	 * this field must be always at first position
	 */
	struct tls_common_ctx c;
	struct tls_credentials *credentials;
};

struct tls_client_ctx {
	/*
	 * Since pointer to tls_client_ctx needs to be casted
	 * to  tls_ctx_common in some functions,
	 * this field must be always at first position
	 */
	struct tls_common_ctx c;
	tls_client_param_t *params; /**< It's reference-counted. */
};

/*! Create an empty TLS context in query context */
struct tls_ctx* tls_new(struct worker_ctx *worker);

/*! Close a TLS context (call gnutls_bye()) */
void tls_close(struct tls_common_ctx *ctx);

/*! Release a TLS context */
void tls_free(struct tls_ctx* tls);

/*! Push new data to TLS context for sending */
int tls_write(uv_write_t *req, uv_handle_t* handle, knot_pkt_t * pkt, uv_write_cb cb);

/*! Unwrap incoming data from a TLS stream and pass them to TCP session.
 * @return the number of newly-completed requests (>=0) or an error code
 */
ssize_t tls_process_input_data(struct session *s, const uint8_t *buf, ssize_t nread);

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


/*! Allocate new client TLS context */
struct tls_client_ctx *tls_client_ctx_new(tls_client_param_t *entry,
					    struct worker_ctx *worker);

/*! Free client TLS context */
void tls_client_ctx_free(struct tls_client_ctx *ctx);

int tls_client_connect_start(struct tls_client_ctx *client_ctx,
			     struct session *session,
			     tls_handshake_cb handshake_cb);

int tls_client_ctx_set_session(struct tls_client_ctx *ctx, struct session *session);


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

