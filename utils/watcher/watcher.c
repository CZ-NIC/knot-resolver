#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "kresconfig.h"
#include "lib/utils.h"
#include "modules/sysrepo/common/sysrepo.h"

#include "worker.h"
#include "watcher.h"
#include "sr_subscriptions.h"

/* 12 hours interval */
#define TST_SECRET_CYCLE	12*60*60*1000


/* default configuration */
struct server_config default_config = {
	.auto_start = false,
	.auto_cache_gc = true,
	.kresd_instances = 1
};

static void tst_secret_check(uv_timer_t *timer, bool timer_update);
static void tst_timer_callback(uv_timer_t *timer)
{
	tst_secret_check(timer, true);
}

static tst_secret_ctx_t * tst_secret_create(uv_loop_t *loop)
{
	struct tst_secret_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx) return NULL;

	if (uv_timer_init(loop, &ctx->timer) != 0) {
		free(ctx);
		return NULL;
	}
	ctx->timer.data = ctx;
	return ctx;
}

static void tst_secret_check(uv_timer_t *timer, bool timer_update)
{
	int ret = 0;
	uv_update_time(timer->loop);

	if(timer_update) {
		uint8_t *base64;
		gnutls_datum_t key_tmp = { NULL, 0 };
		ret = gnutls_session_ticket_key_generate(&key_tmp);
		if (ret){
			kr_log_error("[watcher] failed to generate tls sticket secret, %s", strerror(ret));
			return;
		}

		int32_t len = base64_encode_alloc((uint8_t *)key_tmp.data, sizeof key_tmp.data, &base64);
		if (len < 0) {
			kr_log_error("[watcher] failed to encode tls sticket secret in base64");
			return;
		}

		base64[len-1] = '\0';
		char *secret = (char*) base64;

		kr_log_info("[watcher] generated new secret for tls session ticket\n");
		ret = set_tst_secret(secret);

		free(key_tmp.data);
		free(secret);
	}
	uv_timer_start(timer, &tst_timer_callback, TST_SECRET_CYCLE, 0);
}

static tst_secret_ctx_t * tst_secret_ctx_create(uv_loop_t *loop, bool timer_update)
{
	assert(loop);
	tst_secret_ctx_t *ctx = tst_secret_create(loop);
	if (ctx) {
		tst_secret_check(&ctx->timer, timer_update);
	}
	kr_log_info("[watcher] new context for tls_sticket_secret created\n");
	return ctx;
}

static void tst_secret_destroy(uv_handle_t *timer)
{
	assert(timer);
	struct tst_secret_ctx *ctx = timer->data;
	assert(ctx);
	free(ctx);
}


static void tst_secret_timer_destroy(tst_secret_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
	uv_close((uv_handle_t *)&ctx->timer, &tst_secret_destroy);
}

int tst_secret_timer_init(uv_loop_t *loop)
{
	tst_secret_ctx_t *tst_ctx = the_worker->engine->watcher.tst_secret;

	tst_secret_timer_destroy(tst_ctx);

	tst_ctx = tst_secret_ctx_create(loop, false);
	the_worker->engine->watcher.tst_secret = tst_ctx;
	if (the_worker->engine->watcher.tst_secret == NULL) {
		kr_log_error("[watcher] failed to create tls session ticket secret context");
		return 1;
	}
	return 0;
}

void watcher_init(struct watcher_context *watcher, uv_loop_t *loop)
{
	assert(watcher != NULL);
	if (watcher != NULL) {
		watcher->loop = loop;
		watcher->config = default_config;

		/* Init sysrepo context */
		watcher->sysrepo = sysrepo_ctx_init();

		/* Init timer for tls session ticket secret generation */
		watcher->tst_secret = tst_secret_ctx_create(loop, true);
	}
}

void watcher_deinit(struct watcher_context *watcher)
{
	assert(watcher);
	if (watcher != NULL) {
		sysrepo_ctx_deinit(watcher->sysrepo);
		tst_secret_timer_destroy(watcher->tst_secret);
	}
}