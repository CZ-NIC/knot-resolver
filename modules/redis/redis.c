/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <libknot/db/db.h>
#include <contrib/cleanup.h>
#include <uv.h>

#include "modules/redis/redis.h"
#include "daemon/engine.h"
#include "lib/module.h"
#include "lib/cache.h"

/** @internal Redis API */
const struct kr_cdb_api *cdb_redis(void);

KR_EXPORT
int redis_init(struct kr_module *module)
{
	struct engine *engine = module->data;
	array_push(engine->backends, cdb_redis());
	return kr_ok();
}

KR_EXPORT
int redis_deinit(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* It was currently loaded, close cache */
	if (engine->resolver.cache.api == cdb_redis()) {
		kr_cache_close(&engine->resolver.cache);
	}
	/* Prevent from loading it again */
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		if (strcmp(api->name, "redis") == 0) {
			array_del(engine->backends, i);
			break;
		}
	}
	return kr_ok();
}

KR_MODULE_EXPORT(redis);
