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

#include "lib/module.h"
#include "lib/layer.h"

#define DEBUG_MSG(fmt...) QRDEBUG(NULL, "hint",  fmt)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	return ctx->state;
}

/*
 * Module implementation.
 */

const knot_layer_api_t *hints_layer(void)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.out = &query
	};
	return &_layer;
}

int hints_init(struct kr_module *module)
{
	return 0;
}

int hints_deinit(struct kr_module *module)
{
	return 0;
}

KR_MODULE_EXPORT(hints);
