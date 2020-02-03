#pragma once

#include <stdbool.h>
#include <uv.h>

#include <sysrepo.h>
#include <libyang/libyang.h>
#include <systemd/sd-bus.h>

#include "sysrepo_client.h"

#define PROGRAM_NAME "kres-watcher"
#define KR_WATCHER_VERSION	"0.1"


struct watcher_ctx;
struct server_conf;

extern struct watcher_ctx *the_watcher;
extern struct server_conf server_conf;

struct server_conf{
	bool start_on_boot;
	bool start_cache_gc;
	uint8_t kresd_inst;
	bool persist_conf;
};

struct watcher_ctx {
	sysrepo_uv_ctx_t *sysrepo;
	sd_bus *bus;
	uv_loop_t *loop;
};

int watcher_init(uv_loop_t *loop);

int watcher_deinit(uv_loop_t *loop);

int watcher_run(uv_loop_t *loop);