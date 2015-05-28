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

/**
 * @file stats.c
 * @brief Storage for various counters and metrics from query resolution. 
 *
 * You can either reuse this module to compute statistics or store custom metrics
 * in it via the extensions.
 */

#include <libknot/packet/pkt.h>
#include <ccan/json/json.h>

#include "lib/layer/iterate.h"
#include "lib/rplan.h"
#include "lib/module.h"
#include "lib/layer.h"

/** @internal Compatibility wrapper for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
#define lua_rawlen(L, obj) lua_objlen((L), (obj))
#endif

/* Defaults */
#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "stat",  fmt)

/** @internal Subtract time (best effort) */
float time_diff(struct timeval *begin, struct timeval *end)
{
	return (end->tv_sec - begin->tv_sec) * 1000 +
	       (end->tv_usec - begin->tv_usec) / 1000.0;

}

/** @internal Add to map counter */
static inline void stat_add(map_t *map, const char *key, ssize_t incr)
{
	void *val = map_get(map, key);
	map_set(map, key, (void *)((size_t)val + incr));
}

static int begin(knot_layer_t *ctx, void *module_param)
{
	struct kr_module *module = ctx->api->data;
	map_t *map = module->data;
	stat_add(map, "query.concurrent", 1);
	ctx->data = module_param;
	return ctx->state;
}

static int collect_answer(map_t *map, knot_pkt_t *pkt)
{
	stat_add(map, "answer.total", 1);
	/* Count per-rcode */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:  stat_add(map, "answer.noerror", 1); break;
	case KNOT_RCODE_NXDOMAIN: stat_add(map, "answer.nxdomain", 1); break;
	case KNOT_RCODE_SERVFAIL: stat_add(map, "answer.servfail", 1); break;
	default: break;
	}

	return kr_ok();
}

static int collect(knot_layer_t *ctx)
{
	struct kr_request *param = ctx->data;
	struct kr_module *module = ctx->api->data;
	struct kr_rplan *rplan = &param->rplan;
	map_t *map = module->data;

	/* Collect data on final answer */
	collect_answer(map, param->answer);
	/* Count cached and unresolved */
	if (!EMPTY_LIST(rplan->resolved)) {
		struct kr_query *last = TAIL(rplan->resolved);
		if (last->flags & QUERY_CACHED) {
			stat_add(map, "answer.cached", 1);
		}
		/* Count slow queries (>1000ms) */
		struct kr_query *first = HEAD(rplan->resolved);
		struct timeval now;
		gettimeofday(&now, NULL);
		float elapsed = time_diff(&first->timestamp, &now);
		if (elapsed > 1000.0) {
			stat_add(map, "answer.slow", 1);
		}
	} else {
		stat_add(map, "answer.unresolved", 1);
	}
	/* Query parameters and transport mode */
	stat_add(map, "query.concurrent", -1);
	if (knot_pkt_has_edns(param->answer)) {
		stat_add(map, "query.edns", -1);
		if (knot_pkt_has_dnssec(param->answer)) {
			stat_add(map, "query.dnssec", -1);
		}
	}
	/* Collect data from iterator queries */
	struct kr_query *qry = NULL;
	WALK_LIST(qry, rplan->resolved) {
		if (!(qry->flags & QUERY_CACHED) && qry != TAIL(rplan->resolved)) {
			if (qry->flags & QUERY_TCP) {
				stat_add(map, "iterator.tcp", 1);
			} else {
				stat_add(map, "iterator.udp", 1);
			}
		}
	}
	return ctx->state;
}

/**
 * Set nominal value of a key.
 *
 * Input:  { key, val }
 *
 */
static char* stats_set(void *env, struct kr_module *module, const char *args)
{
	map_t *map = module->data;
	auto_free char *pair = strdup(args);
	char *val = strchr(pair, ' ');
	if (val) {
		*val = '\0';
		size_t number = strtoul(val + 1, NULL, 10);
		map_set(map, pair, (void *)number);
	}

	return NULL;
}

/**
 * Retrieve metrics by key.
 *
 * Input:  string key
 * Output: number value
 */
static char* stats_get(void *env, struct kr_module *module, const char *args)
{
	map_t *map = module->data;
	if (!map_contains(map, args)) {
		return NULL;
	}

	/* Expecting CHAR_BIT to be 8, this is a safe bet */
	char *ret = malloc(3 * sizeof(ret) + 2);
	if (!ret) {
		return NULL;
	}

	void *val = map_get(map, args);
	sprintf(ret, "%zu", (size_t) val);
	return ret;
}

static int list_entry(const char *key, void *val, void *baton)
{
	JsonNode *root = baton;
	size_t number = (size_t) val;
	json_append_member(root, key, json_mknumber(number));
	return 0;
}

/**
 * List observed metrics.
 *
 * Output: { key: val, ... }
 */
static char* stats_list(void *env, struct kr_module *module, const char *args)
{
	map_t *map = module->data;
	JsonNode *root = json_mkobject();
	map_walk_prefixed(map, args ? args : "", list_entry, root);
	char *ret = json_encode(root);
	json_delete(root);
	return ret;
}

/*
 * Module implementation.
 */

const knot_layer_api_t *stats_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
		.begin = &begin,
		.finish = &collect,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

int stats_init(struct kr_module *module)
{
	map_t *map = malloc(sizeof(*map));
	if (!map) {
		return kr_error(ENOMEM);
	}
	*map = map_make();
	module->data = map;
	return kr_ok();
}

int stats_deinit(struct kr_module *module)
{
	map_t *map = module->data;
	if (map) {
		map_clear(map);
		free(map);
	}
	return kr_ok();
}

struct kr_prop *stats_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &stats_set,    "set", "Set {key, val} metrics.", },
	    { &stats_get,    "get", "Get metrics for given key.", },
	    { &stats_list,   "list", "List observed metrics.", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(stats);
