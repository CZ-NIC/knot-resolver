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

#include <libknot/packet/pkt.h>

#include "lib/module.h"
#include "lib/layer.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies",  fmt)

/*
 * Module implementation.
 */

#if 0
KR_EXPORT
const knot_layer_api_t *cookies_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = { 0,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int cookies_init(struct kr_module *module)
{
	DEBUG_MSG(NULL, "%s", "Loaded.\n");

	module->data = NULL;
	return kr_ok();
}

KR_EXPORT
int  cookies_deinit(struct kr_module *module)
{
	DEBUG_MSG(NULL, "%s", "Unloaded.\n");

	return kr_ok();
}
#endif

KR_MODULE_EXPORT(cookies);
