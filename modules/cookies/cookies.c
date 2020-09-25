/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>

#include "daemon/engine.h"
#include "lib/layer.h"
#include "modules/cookies/cookiectl.h"
#include "modules/cookies/cookiemonster.h"

/**
 * Get/set DNS cookie related stuff.
 *
 * Input: { name: value, ... }
 * Output: current configuration
 */
static char *cookies_config(void *env, struct kr_module *module,
                            const char *args)
{
	struct kr_cookie_ctx *cookie_ctx = module->data;
	assert(cookie_ctx);

	/* Apply configuration, if any. */
	config_apply(cookie_ctx, args);

	/* Return current configuration. */
	return config_read(cookie_ctx);
}

/*
 * Module implementation.
 */

KR_EXPORT
int cookies_init(struct kr_module *module)
{
	/* The function answer_finalize() in resolver is called before any
	 * .finish callback. Therefore this layer does not use it. */
	static kr_layer_api_t layer = {
		.begin = &check_request,
		.consume = &check_response
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { &cookies_config, "config", "Empty value to return current configuration.", },
	    { NULL, NULL, NULL }
	};
	module->props = props;

	struct engine *engine = module->data;

	struct kr_cookie_ctx *cookie_ctx = &engine->resolver.cookie_ctx;

	int ret = config_init(cookie_ctx);
	if (ret != kr_ok()) {
		return ret;
	}

	/* Replace engine pointer. */
	module->data = cookie_ctx;

	return kr_ok();
}

KR_EXPORT
int cookies_deinit(struct kr_module *module)
{
	struct kr_cookie_ctx *cookie_ctx = module->data;

	config_deinit(cookie_ctx);

	return kr_ok();
}

KR_MODULE_EXPORT(cookies)
