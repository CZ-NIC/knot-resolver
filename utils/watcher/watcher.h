#pragma once

#include <stdbool.h>
#include <uv.h>

#include <sysrepo.h>
#include <libyang/libyang.h>
#include <systemd/sd-bus.h>

#include "modules/sysrepo/common/sysrepo.h"


typedef struct server_config {
	bool auto_start;
	bool auto_cache_gc;
	uint8_t kresd_instances;
};

typedef struct tst_secret_ctx {
	uv_timer_t timer;
} tst_secret_ctx_t;

typedef struct sdbus_ctx {

} sdbus_ctx_t;

struct watcher_context {
	uv_loop_t *loop;
	sysrepo_uv_ctx_t *sysrepo;
	sdbus_ctx_t *sdbus;
	tst_secret_ctx_t *tst_secret;
	struct server_config config;
};

void watcher_init(struct watcher_context *watcher, uv_loop_t *loop);

void watcher_deinit(struct watcher_context *watcher);