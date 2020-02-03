#pragma once

#include <systemd/sd-bus.h>
#include <uv.h>

#define UNIT_START			"StartUnit"
#define UNIT_STOP			"StopUnit"
#define UNIT_RESTART 		"RestartUnit"


int sdbus_client_init(uv_loop_t *loop);

int sdbus_client_deinit(uv_loop_t *loop);

int control_knot_resolver(const char *method);

int control_cache_gc(const char *method);

