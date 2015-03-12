/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <limits.h>

#include <libknot/errcode.h>
#include <libknot/internal/sockaddr.h>
#include <libknot/internal/mem.h>

#include "lib/context.h"
#include "lib/defines.h"
#include "lib/rplan.h"

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(struct kr_context));
	ctx->pool = mm;

	return KNOT_EOK;
}

int kr_context_deinit(struct kr_context *ctx)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->cache) {
		kr_cache_close(ctx->cache);
	}

	for (size_t i = 0; i < ctx->mod_loaded; ++i) {
		kr_module_unload(&ctx->modules[i]);
	}

	return KNOT_EOK;
}

int kr_context_register(struct kr_context *ctx, const char *module_name)
{
	size_t last = ctx->mod_loaded;
	int ret = mreserve((char **) &ctx->modules, sizeof(struct kr_module),
	                   last + 1, 0, &ctx->mod_reserved);
	if (ret < 0) {
		return kr_error(ENOMEM);
	}

	struct kr_module *mod = &ctx->modules[last];
	ret = kr_module_load(mod, module_name, NULL);
	if (ret != 0) {
		return ret;
	}

	ctx->mod_loaded += 1;
	return kr_ok();
}
