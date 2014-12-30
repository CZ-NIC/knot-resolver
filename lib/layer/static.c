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

#include "lib/layer/static.h"

static int reset(knot_layer_t *ctx)
{
	/* TODO: sync, cleanup after resolution */
	return ctx->state;
}

static int begin(knot_layer_t *ctx, void *param)
{
	ctx->data = param;

	struct kr_context *resolve = ((struct kr_layer_param *)param)->ctx;
	assert(resolve);

	/* TODO: read static hosts file */

	return ctx->state;
}

/*! \brief Module implementation. */
static const knot_layer_api_t LAYER_STATIC_MODULE = {
	&begin,
	&reset,
	NULL,
	NULL,
	NULL,
	NULL
};

const knot_layer_api_t *layer_static_module(void)
{
	return &LAYER_STATIC_MODULE;
}
