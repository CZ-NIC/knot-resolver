/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <contrib/cleanup.h>

#include "daemon/engine.h"
#include "lib/cdb.h"
#include "lib/module.h"
#include "lib/cache.h"

/** @internal Redis API */
const struct kr_cdb_api *cdb_memcached(void);

KR_EXPORT
int memcached_init(struct kr_module *module)
{
	struct engine *engine = module->data;
	array_push(engine->backends, cdb_memcached());
	return 0;
}

KR_EXPORT
int memcached_deinit(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* It was currently loaded, close cache */
	if (engine->resolver.cache.api == cdb_memcached()) {
		kr_cache_close(&engine->resolver.cache);
	}
	/* Prevent from loading it again */
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		if (strcmp(api->name, "memcached") == 0) {
			array_del(engine->backends, i);
			break;
		}
	}
	return 0;
}

KR_MODULE_EXPORT(memcached);
