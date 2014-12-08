/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
