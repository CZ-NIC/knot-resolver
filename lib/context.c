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

#include <libknot/errcode.h>
#include <libknot/internal/sockaddr.h>
#include "lib/context.h"
#include "lib/rplan.h"

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kr_context));

	ctx->pool = mm;

	ctx->cache = kr_cache_open("/tmp/kresolved", mm);
	if (ctx->cache == NULL) {
		fprintf(stderr, "Cache directory '/tmp/kresolved' not exists, exitting.\n");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int kr_context_deinit(struct kr_context *ctx)
{
	kr_cache_close(ctx->cache);

	return KNOT_EOK;
}
