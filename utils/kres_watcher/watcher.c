#include <sys/sysinfo.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <assert.h>
#include <uv.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "kresconfig.h"
#include "base64.h"
#include "lib/utils.h"
#include "watcher.h"
#include "sysrepo_client.h"
#include "sdbus_client.h"
#include "modules/sysrepo/common/sysrepo_utils.h"

/* 12 hours interval */
#define TST_SECRET_CYCLE	12*60*60*1000


/* default configuration */
struct knot_resolver_conf config = {
	.persistent_config = false,
	.auto_start = false,
	.kresd_instances_num = 0,
	.kresd = NULL,
	.cache_gc = {
		.auto_start = false,
		.running = false
	}
};

struct watcher_ctx the_watcher_value;
struct watcher_ctx *the_watcher = NULL;

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

	if(timer_update){
		kr_log_info("[watcher] generating new tls sticket secret\n");

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

		printf("%s\n", secret);
		set_tst_secret(secret);

		free(key_tmp.data);
		free(secret);
	}

	uv_timer_start(timer, &tst_timer_callback, TST_SECRET_CYCLE, 0);
}

static tst_secret_ctx_t * tst_secret_timer_create(uv_loop_t *loop)
{
	assert(loop);
	tst_secret_ctx_t *ctx = tst_secret_create(loop);
	if (ctx) {
		tst_secret_check(&ctx->timer, false);
	}
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
	tst_secret_ctx_t *tst_ctx = the_watcher->tst_secret;

	tst_secret_timer_destroy(tst_ctx);

	tst_ctx = tst_secret_timer_create(loop);
	the_watcher->tst_secret = tst_ctx;
	if (the_watcher->tst_secret == NULL) {
		kr_log_error("[watcher] failed to create tls session ticket secret context");
		return 1;
	}
	return 0;
}

int watcher_init(uv_loop_t *loop)
{
	assert(the_watcher == NULL);

	int ret = 0;
	/* create watcher */
	struct watcher_ctx *watcher = &the_watcher_value;
	memset(watcher, 0, sizeof(*watcher));

	watcher->loop = loop;
	watcher->tst_secret = tst_secret_timer_create(loop);
	watcher->sysrepo = sysrepo_watcher_create(loop);
	watcher->sdbus = sdbus_watcher_create(loop);

	the_watcher = watcher;
	loop->data = the_watcher;

	/* Start Knot Resolver if start on boot */
	if (config.auto_start){

	}

	return ret;
}

int watcher_deinit(uv_loop_t *loop)
{
	int ret = 0;
	struct watcher_ctx *watcher = the_watcher;
	assert(watcher);

	sysrepo_client_deinit(watcher->sysrepo);
	sdbus_watcher_deinit(watcher->sdbus);

	the_watcher =NULL;

	return ret;
}
