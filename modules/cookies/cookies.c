/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

KR_EXPORT
const kr_layer_api_t *cookies_layer(struct kr_module *module)
{
	/* The function answer_finalize() in resolver is called before any
	 * .finish callback. Therefore this layer does not use it. */

	static kr_layer_api_t _layer = {
		.begin = &check_request,
		.consume = &check_response
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
struct kr_prop *cookies_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &cookies_config, "config", "Empty value to return current configuration.", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(cookies)
