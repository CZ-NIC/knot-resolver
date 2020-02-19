#pragma once

#include <systemd/sd-bus.h>
#include <uv.h>

#define UNIT_START			"StartUnit"
#define UNIT_STOP			"StopUnit"
#define UNIT_RESTART 		"RestartUnit"


typedef struct sdbus_uv_ctx sdbus_uv_ctx_t;

typedef void (*sdbus_uv_cb)(sdbus_uv_ctx_t *sdbus_ctx, int status);

/** Context for our sysrepo subscriptions.
 * might add some other fields in future */
struct sdbus_uv_ctx {
	sd_bus *bus;
	sdbus_uv_cb callback;
	uv_poll_t uv_handle;
};

int watch_kresd(sd_bus *bus, sd_bus_slot **slot, const char *instance);

int watch_cache_gc(sd_bus *bus, sd_bus_slot **slot);

int sdbus_watcher_init(uv_loop_t *loop);

sdbus_uv_ctx_t *sdbus_watcher_create(uv_loop_t *loop);

void sdbus_watcher_deinit(sdbus_uv_ctx_t *sdbus_ctx);

int kresd_ctl(sd_bus *bus, const char *method, const char *instance);

int cache_gc_ctl(sd_bus *bus, const char *method);

