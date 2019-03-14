/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

