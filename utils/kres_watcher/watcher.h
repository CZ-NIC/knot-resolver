#pragma once

#include <stdbool.h>
#include <uv.h>

#include <sysrepo.h>
#include <libyang/libyang.h>
#include <systemd/sd-bus.h>

#include "sysrepo_client.h"
#include "sdbus_client.h"

#define PROGRAM_NAME "kres-watcher"
#define KR_WATCHER_VERSION	"0.1"


struct watcher_ctx;
struct knot_resolver_conf;

extern struct watcher_ctx *the_watcher;
extern struct knot_resolver_conf config;

typedef struct tst_secret_ctx {
	uv_timer_t timer;
	time_t last_updated;
} tst_secret_ctx_t;

struct cache_gc{
	bool auto_start;
	bool running;
	sd_bus_slot *slot;
};

struct kresd_instance {
	bool running;
	sd_bus_slot *slot;
};

struct knot_resolver_conf {
	bool start_on_boot;
	bool persistent_config;
	struct cache_gc cache_gc;
	uint8_t kresd_instances_num;
	struct kresd_instance *kresd;
};

struct watcher_ctx {
	uv_loop_t *loop;
	sysrepo_uv_ctx_t *sysrepo;
	sdbus_uv_ctx_t *sdbus;
	struct tst_secret_ctx *tst_secret;
};

int watcher_init(uv_loop_t *loop);

int watcher_deinit();

int tst_secret_timer_init(uv_loop_t *loop);
