/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/cookies/control.h"

void kr_cookie_ctx_init(struct kr_cookie_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->clnt.current.alg_id = ctx->clnt.recent.alg_id = -1;
	ctx->srvr.current.alg_id = ctx->srvr.recent.alg_id = -1;

	ctx->cache_ttl = DFLT_COOKIE_TTL;
}
