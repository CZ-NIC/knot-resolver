/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <uv.h>

#include "lib/utils.h"

/* Style: "local/static" identifiers are usually named tst_* */

/** The number of seconds between synchronized rotation of TLS session ticket key. */
#define TST_KEY_LIFETIME 4096

/** Value from gnutls:lib/ext/session_ticket.c
 * Beware: changing this needs to change the hashing implementation. */
#define SESSION_KEY_SIZE 64

/** Compile-time support for setting the secret. */
/* This is not secure with TLS <= 1.2 but TLS 1.3 and secure configuration
 * is not available in GnuTLS yet. See https://gitlab.com/gnutls/gnutls/issues/477
#ifndef TLS_SESSION_RESUMPTION_SYNC
	#define TLS_SESSION_RESUMPTION_SYNC (GNUTLS_VERSION_NUMBER >= 0x030603)
#endif
*/

#if GNUTLS_VERSION_NUMBER < 0x030400
	/* It's of little use anyway.  We may get the secret through lua,
	 * which creates a copy outside of our control. */
	#define gnutls_memset memset
#endif

#ifdef GNUTLS_DIG_SHA3_512
	#define TST_HASH GNUTLS_DIG_SHA3_512
#else
	#define TST_HASH abort()
#endif

/** Fields are internal to tst_key_* functions. */
typedef struct tls_session_ticket_ctx {
	uv_timer_t timer;	/**< timer for rotation of the key */
	unsigned char key[SESSION_KEY_SIZE]; /**< the key itself */
	bool has_secret;	/**< false -> key is random for each epoch */
	uint16_t hash_len;	/**< length of `hash_data` */
	char hash_data[];	/**< data to hash to obtain `key`;
				 *   it's `time_t epoch` and then the secret string */
} tst_ctx_t;

/** Check invariants, based on gnutls version. */
static bool tst_key_invariants(void)
{
	static int result = 0; /*< cache for multiple invocations */
	if (result) return result > 0;
	bool ok = true;
	#if TLS_SESSION_RESUMPTION_SYNC
		/* SHA3-512 output size may never change, but let's check it anyway :-) */
		ok = ok && gnutls_hash_get_len(TST_HASH) == SESSION_KEY_SIZE;
	#endif
	/* The ticket key size might change in a different gnutls version. */
	gnutls_datum_t key = { 0, 0 };
	ok = ok && gnutls_session_ticket_key_generate(&key) == 0
		&& key.size == SESSION_KEY_SIZE;
	free(key.data);
	result = ok ? 1 : -1;
	return ok;
}

/** Create the internal structures and copy the secret. Beware: secret must be kept secure. */
static tst_ctx_t * tst_key_create(const char *secret, size_t secret_len, uv_loop_t *loop)
{
	const size_t hash_len = sizeof(time_t) + secret_len;
	if (secret_len &&
	    (!secret || hash_len > UINT16_MAX || hash_len < secret_len)) {
		assert(!EINVAL);
		return NULL;
		/* reasonable secret_len is best enforced in config API */
	}
	if (!tst_key_invariants()) {
		assert(!EFAULT);
		return NULL;
	}
	#if !TLS_SESSION_RESUMPTION_SYNC
		if (secret_len) {
			kr_log_error("[tls] session ticket: secrets were not enabled at compile-time (your GnuTLS version is not supported)\n");
			return NULL; /* ENOTSUP */
		}
	#endif

	tst_ctx_t *ctx = malloc(sizeof(*ctx) + hash_len); /* can be slightly longer */
	if (!ctx) return NULL;
	ctx->has_secret = secret_len > 0;
	ctx->hash_len = hash_len;
	if (secret_len) {
		memcpy(ctx->hash_data + sizeof(time_t), secret, secret_len);
	}

	if (uv_timer_init(loop, &ctx->timer) != 0) {
		free(ctx);
		return NULL;
	}
	ctx->timer.data = ctx;
	return ctx;
}

/** Random variant of secret rotation: generate into key_tmp and copy. */
static int tst_key_get_random(tst_ctx_t *ctx)
{
	gnutls_datum_t key_tmp = { NULL, 0 };
	int err = gnutls_session_ticket_key_generate(&key_tmp);
	if (err) return kr_error(err);
	if (key_tmp.size != SESSION_KEY_SIZE) {
		assert(!EFAULT);
		return kr_error(EFAULT);
	}
	memcpy(ctx->key, key_tmp.data, SESSION_KEY_SIZE);
	gnutls_memset(key_tmp.data, 0, SESSION_KEY_SIZE);
	free(key_tmp.data);
	return kr_ok();
}

/** Recompute the session ticket key, if epoch has changed or forced. */
static int tst_key_update(tst_ctx_t *ctx, time_t epoch, bool force_update)
{
	if (!ctx || ctx->hash_len < sizeof(epoch)) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	/* documented limitation: time_t and endianess must match
	 * on instances sharing a secret */
	if (!force_update && memcmp(ctx->hash_data, &epoch, sizeof(epoch)) == 0) {
		return kr_ok(); /* we are up to date */
	}
	memcpy(ctx->hash_data, &epoch, sizeof(epoch));

	if (!ctx->has_secret) {
		return tst_key_get_random(ctx);
	}
	/* Otherwise, deterministic variant of secret rotation, if supported. */
	#if !TLS_SESSION_RESUMPTION_SYNC
		assert(false);
		return kr_error(ENOTSUP);
	#else
		int err = gnutls_hash_fast(TST_HASH, ctx->hash_data,
					   ctx->hash_len, ctx->key);
		return err == 0 ? kr_ok() : kr_error(err);
	#endif
}

/** Free all resources of the key (securely). */
static void tst_key_destroy(uv_handle_t *timer)
{
	assert(timer);
	tst_ctx_t *ctx = timer->data;
	assert(ctx);
	gnutls_memset(ctx, 0, offsetof(tst_ctx_t, hash_data) + ctx->hash_len);
	free(ctx);
}

static void tst_key_check(uv_timer_t *timer, bool force_update);
static void tst_timer_callback(uv_timer_t *timer)
{
	tst_key_check(timer, false);
}

/** Update the ST key if needed and reschedule itself via the timer. */
static void tst_key_check(uv_timer_t *timer, bool force_update)
{
	tst_ctx_t *stst = (tst_ctx_t *)timer->data;
	/* Compute the current epoch. */
	struct timeval now;
	if (gettimeofday(&now, NULL)) {
		kr_log_error("[tls] session ticket: gettimeofday failed, %s\n",
				strerror(errno));
		return;
	}
	uv_update_time(timer->loop); /* to have sync. between real and mono time */
	const time_t epoch = now.tv_sec / TST_KEY_LIFETIME;
	/* Update the key; new sessions will fetch it from the location.
	 * Old ones hopefully can't get broken by that; documentation
	 * for gnutls_session_ticket_enable_server() doesn't say. */
	int err = tst_key_update(stst, epoch, force_update);
	if (err) {
		assert(err != kr_error(EINVAL));
		kr_log_error("[tls] session ticket: failed rotation, err = %d\n", err);
	}
	/* Reschedule. */
	const time_t tv_sec_next = (epoch + 1) * TST_KEY_LIFETIME;
	const uint64_t ms_until_second = 1000 - (now.tv_usec + 501) / 1000;
	const uint64_t remain_ms = (tv_sec_next - now.tv_sec - 1) * (uint64_t)1000
				 + ms_until_second + 1;
	/* ^ +1 because we don't want to wake up half a millisecond before the epoch! */
	assert(remain_ms < (TST_KEY_LIFETIME + 1 /*rounding tolerance*/) * 1000);
	kr_log_verbose("[tls] session ticket: epoch %"PRIu64
			", scheduling rotation check in %"PRIu64" ms\n",
			(uint64_t)epoch, remain_ms);
	err = uv_timer_start(timer, &tst_timer_callback, remain_ms, 0);
	if (err) {
		assert(false);
		kr_log_error("[tls] session ticket: failed to schedule, err = %d\n", err);
	}
}

/* Implementation for prototypes from ./tls.h */

void tls_session_ticket_enable(struct tls_session_ticket_ctx *ctx, gnutls_session_t session)
{
	assert(ctx && session);
	const gnutls_datum_t gd = {
		.size = SESSION_KEY_SIZE,
		.data = ctx->key,
	};
	int err = gnutls_session_ticket_enable_server(session, &gd);
	if (err) {
		kr_log_error("[tls] failed to enable session tickets: %s (%d)\n",
				gnutls_strerror_name(err), err);
		/* but continue without tickets */
	}
}

tst_ctx_t * tls_session_ticket_ctx_create(uv_loop_t *loop, const char *secret,
					  size_t secret_len)
{
	assert(loop && (!secret_len || secret));
	#if GNUTLS_VERSION_NUMBER < 0x030500
		/* We would need different SESSION_KEY_SIZE; avoid assert. */
		return NULL;
	#endif
	tst_ctx_t *ctx = tst_key_create(secret, secret_len, loop);
	if (ctx) {
		tst_key_check(&ctx->timer, true);
	}
	return ctx;
}

void tls_session_ticket_ctx_destroy(tst_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
	uv_close((uv_handle_t *)&ctx->timer, &tst_key_destroy);
}

