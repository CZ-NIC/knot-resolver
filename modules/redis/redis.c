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

#include <libknot/internal/namedb/namedb.h>
#include <uv.h>

#include "modules/redis/redis.h"
#include "daemon/engine.h"
#include "lib/module.h"
#include "lib/cache.h"

/** @internal Redis API */
extern const namedb_api_t *namedb_redis_api(void);

/** @internal Make redis options. */
void *namedb_redis_mkopts(const char *conf_, size_t maxsize)
{
	auto_free char *conf = strdup(conf_);
	struct redis_cli *cli = malloc(sizeof(*cli));
	if (!cli || !conf) {
		free(cli);
		return NULL;
	}
	/* Parse database */
	memset(cli, 0, sizeof(*cli));
	char *bp = conf;
	char *p = strchr(bp, '@');
	if (p) {
		*p = '\0';
		cli->database = atoi(conf);
		bp = (p + 1);
	}
	/* Parse host / ip / sock */
	if (access(bp, W_OK) == 0) { /* UNIX */
		cli->addr = strdup(bp);
		return cli;
	}
	struct sockaddr_in6 ip6;
	p = strchr(bp, ':');
	if (!p) { /* IPv4 */
		cli->addr = strdup(bp);
		cli->port = REDIS_PORT;
		return cli;
	}
	if (!strchr(p + 1, ':')) { /* IPv4 + port */
		*p = '\0';
		cli->addr = strdup(bp);
		cli->port = atoi(p + 1);
	} else { /* IPv6 */
		if (uv_ip6_addr(bp, 0, &ip6) == 0) {
			cli->addr = strdup(bp);
			cli->port = REDIS_PORT;
		} else { /* IPv6 + port */
			p = strrchr(bp, ':');
			*p = '\0';
			cli->addr = strdup(bp);
			cli->port = atoi(p + 1);
		}
	}
	return cli;
}

KR_EXPORT
int redis_init(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* Register new storage option */
	static struct storage_api redis = {
		"redis://", namedb_redis_api, namedb_redis_mkopts
	};
	array_push(engine->storage_registry, redis);
	return kr_ok();
}

KR_EXPORT
int redis_deinit(struct kr_module *module)
{
	struct engine *engine = module->data;
	/* It was currently loaded, close cache */
	if (engine->resolver.cache.api == namedb_redis_api()) {
		kr_cache_close(&engine->resolver.cache);
	}
	/* Prevent from loading it again */
	for (unsigned i = 0; i < engine->storage_registry.len; ++i) {
		struct storage_api *storage = &engine->storage_registry.at[i];
		if (strcmp(storage->prefix, "redis://") == 0) {
			array_del(engine->storage_registry, i);
			break;
		}
	}
	return kr_ok();
}

KR_MODULE_EXPORT(redis);
