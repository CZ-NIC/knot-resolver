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

#include <libknot/internal/namedb/namedb.h>

#include "daemon/engine.h"
#include "lib/module.h"
#include "lib/cache.h"

/** @internal Memcached API */
extern const namedb_api_t *namedb_memcached_api(void);

/** @internal Make memcached options. */
void *namedb_memcached_mkopts(const char *conf, size_t maxsize)
{
	return strdup(conf);
}

int kmemcached_init(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* Register new storage option */
	static struct storage_api memcached = {
		"memcached://", namedb_memcached_api, namedb_memcached_mkopts
	};
	array_push(engine->storage_registry, memcached);
	return kr_ok();
}

int kmemcached_deinit(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* It was currently loaded, close cache */
	if (engine->resolver.cache.api == namedb_memcached_api()) {
		kr_cache_close(&engine->resolver.cache);
	}
	/* Prevent from loading it again */
	for (unsigned i = 0; i < engine->storage_registry.len; ++i) {
		struct storage_api *storage = &engine->storage_registry.at[i];
		if (strcmp(storage->prefix, "memcached://") == 0) {
			array_del(engine->storage_registry, i);
			break;
		}
	}
	return kr_ok();
}

KR_MODULE_EXPORT(kmemcached);
