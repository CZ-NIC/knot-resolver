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

/* \brief Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	const char *addr;
};

/* Initialize with SBELT name servers. */
#define U8(x) (const uint8_t *)(x)
#define HINT_COUNT 13
static const struct hint_info SBELT[HINT_COUNT] = {
        { U8("\x01""a""\x0c""root-servers""\x03""net"), "198.41.0.4" },
        { U8("\x01""b""\x0c""root-servers""\x03""net"), "192.228.79.201" },
        { U8("\x01""c""\x0c""root-servers""\x03""net"), "192.33.4.12" },
        { U8("\x01""d""\x0c""root-servers""\x03""net"), "199.7.91.13" },
        { U8("\x01""e""\x0c""root-servers""\x03""net"), "192.203.230.10" },
        { U8("\x01""f""\x0c""root-servers""\x03""net"), "192.5.5.241" },
        { U8("\x01""g""\x0c""root-servers""\x03""net"), "192.112.36.4" },
        { U8("\x01""h""\x0c""root-servers""\x03""net"), "128.63.2.53" },
        { U8("\x01""i""\x0c""root-servers""\x03""net"), "192.36.148.17" },
        { U8("\x01""j""\x0c""root-servers""\x03""net"), "192.58.128.30" },
        { U8("\x01""k""\x0c""root-servers""\x03""net"), "193.0.14.129" },
        { U8("\x01""l""\x0c""root-servers""\x03""net"), "199.7.83.42" },
        { U8("\x01""m""\x0c""root-servers""\x03""net"), "202.12.27.33" }
};

static int reset(knot_layer_t *ctx)
{
	printf("loading sbelt\n");

	return ctx->state;
}

static int begin(knot_layer_t *ctx, void *param)
{
	ctx->data = param;

	struct kr_context *resolve = ((struct kr_layer_param *)param)->ctx;
	assert(resolve);

	/* Initialize static root hints. */
	struct sockaddr_storage ss;
	for (unsigned i = 0; i < HINT_COUNT; ++i) {
		sockaddr_set(&ss, AF_INET, SBELT[i].addr, 53);
		kr_slist_add(resolve, U8(""), (struct sockaddr *)&ss);
	}

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
