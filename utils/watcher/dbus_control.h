#pragma once

#include <uv.h>
#include <systemd/sd-bus.h>

#define UNIT_START			"StartUnit"
#define UNIT_STOP			"StopUnit"
#define UNIT_RESTART 		"RestartUnit"


typedef struct sdbus_ctx sdbus_ctx_t;

typedef void (*sdbus_cb)(sdbus_ctx_t *sdbus_ctx, int status);

/** Context for sdbus.
* might add some other fields in future */
struct sdbus_uv_ctx {
	sd_bus *bus;
	sdbus_cb callback;
	uv_poll_t uv_handle;
};

int kresd_get_status(const char *instance, char **status);

int cache_gc_get_status(char **status);

int kresd_ctl(const char *method, const char *instance);

int cache_gc_ctl(const char *method);
