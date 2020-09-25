/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/module.h"
#include "lib/cache/api.h"

/** Module implementation. */
int cache_init(struct kr_module *self)
{
	static const kr_layer_api_t layer = {
		.produce = &cache_peek,
		.consume = &cache_stash,
	};
	self->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(cache) /* useless for builtin module, but let's be consistent */

