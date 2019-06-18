/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
 *
 * sd_watchdog module implements support for systemd watchdog supervision */

#include <systemd/sd-daemon.h>
#include <uv.h>

#include "daemon/bindings/impl.h"
#include "lib/utils.h"

struct watchdog_config {
	bool enabled;
	uint64_t timeout_usec;
	uv_timer_t timer;
};

static void keepalive_ping(uv_timer_t *timer)
{
	sd_notify(0, "WATCHDOG=1");
	kr_log_info("[sd_watchdog] sent keepalive\n");  // TODO remove?
}

KR_EXPORT
int sd_watchdog_init(struct kr_module *module)
{
	static kr_layer_api_t layer = { };
	layer.data = module;
	module->layer = &layer;
	module->props = NULL;

	struct watchdog_config *conf = malloc(sizeof(*conf));
	if (!conf) {
		return kr_error(ENOMEM);
	}
	memset(conf, 0, sizeof(*conf));
	module->data = conf;

	kr_log_info("[sd_watchdog] INIT\n");  // TODO rmeove

	/* Check if watchdog is enabled */
	conf->enabled = (bool)sd_watchdog_enabled(1, &conf->timeout_usec);
	if (!conf->enabled) {
		kr_log_verbose("[sd_watchdog] disabled\n");
		return kr_ok();
	}
	kr_log_info("[sd_watchdog] enabled, timeout %ld usec\n", conf->timeout_usec);

	uint64_t delay_ms = (conf->timeout_usec / 1000) / 2;
	if (delay_ms == 0) {
		return kr_error(EINVAL);  // TODO: is this a proper way to handle it?
	}

	uv_loop_t *loop = uv_default_loop();
	uv_timer_init(loop, &conf->timer);
	int ret = uv_timer_start(&conf->timer, keepalive_ping, delay_ms, delay_ms);
	if (ret != 0) {
		return kr_error(EINVAL);  // TODO change code, error log
	}

	kr_log_info("[sd_watchdog] all set! repeat - %ld ms\n", delay_ms);  // TODO rmeove

	return kr_ok();
}

KR_EXPORT
int sd_watchdog_deinit(struct kr_module *module)
{
	struct stat_data *conf = module->data;
	if (conf) {
		free(conf);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(sd_watchdog)
