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

#include <uv.h>
#include <contrib/cleanup.h>
#include <libknot/descriptor.h>

#include "lib/cache.h"
#include "daemon/bindings.h"
#include "daemon/worker.h"

/** @internal Annotate for static checkers. */
KR_NORETURN int lua_error (lua_State *L);

/** @internal Prefix error with file:line */
static int format_error(lua_State* L, const char *err)
{
	lua_Debug d;
	lua_getstack(L, 1, &d);
	/* error message prefix */
	lua_getinfo(L, "Sln", &d);
	if (strncmp(d.short_src, "[", 1) != 0) {
		lua_pushstring(L, d.short_src);
		lua_pushstring(L, ":");
		lua_pushnumber(L, d.currentline);
		lua_pushstring(L, ": error: ");
		lua_concat(L, 4);
	} else {
		lua_pushstring(L, "error: ");
	}
	/* error message */
	lua_pushstring(L, err);
	lua_concat(L,  2);
	return 1;
}

/** List loaded modules */
static int mod_list(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	lua_newtable(L);
	for (unsigned i = 0; i < engine->modules.len; ++i) {
		struct kr_module *module = engine->modules.at[i];
		lua_pushstring(L, module->name);
		lua_rawseti(L, -2, i + 1);
	}
	return 1;
}

/** Load module. */
static int mod_load(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n != 1 || !lua_isstring(L, 1)) {
		format_error(L, "expected 'load(string name)'");
		lua_error(L);
	}
	/* Parse precedence declaration */
	auto_free char *declaration = strdup(lua_tostring(L, 1));
	if (!declaration) {
		return kr_error(ENOMEM);
	}
	const char *name = strtok(declaration, " ");
	const char *precedence = strtok(NULL, " ");
	const char *ref = strtok(NULL, " ");
	/* Load engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_register(engine, name, precedence, ref);
	if (ret != 0) {
		if (ret == kr_error(EIDRM)) {
			format_error(L, "referenced module not found");
		} else {
			format_error(L, kr_strerror(ret));
		}
		lua_error(L);
	}

	lua_pushboolean(L, 1);
	return 1;
}

/** Unload module. */
static int mod_unload(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n != 1 || !lua_isstring(L, 1)) {
		format_error(L, "expected 'unload(string name)'");
		lua_error(L);
	}
	/* Unload engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_unregister(engine, lua_tostring(L, 1));
	if (ret != 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}

	lua_pushboolean(L, 1);
	return 1;
}

int lib_modules(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",   mod_list },
		{ "load",   mod_load },
		{ "unload", mod_unload },
		{ NULL, NULL }
	};

	register_lib(L, "modules", lib);
	return 1;
}

/** Append 'addr = {port = int, udp = bool, tcp = bool}' */
static int net_list_add(const char *key, void *val, void *ext)
{
	lua_State *L = (lua_State *)ext;
	endpoint_array_t *ep_array = val;
	lua_newtable(L);
	for (size_t i = ep_array->len; i--;) {
		struct endpoint *ep = ep_array->at[i];
		lua_pushinteger(L, ep->port);
		lua_setfield(L, -2, "port");
		lua_pushboolean(L, ep->flags & NET_UDP);
		lua_setfield(L, -2, "udp");
		lua_pushboolean(L, ep->flags & NET_TCP);
		lua_setfield(L, -2, "tcp");
	}
	lua_setfield(L, -2, key);
	return kr_ok();
}

/** List active endpoints. */
static int net_list(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	lua_newtable(L);
	map_walk(&engine->net.endpoints, net_list_add, L);
	return 1;
}

/** Listen on interface address list. */
static int net_listen_iface(lua_State *L, int port)
{
	/* Expand 'addr' key if exists */
	lua_getfield(L, 1, "addr");
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		lua_pushvalue(L, 1);
	}

	/* Bind to address list */
	struct engine *engine = engine_luaget(L);
	size_t count = lua_rawlen(L, -1);
	for (size_t i = 0; i < count; ++i) {
		lua_rawgeti(L, -1, i + 1);
		int ret = network_listen(&engine->net, lua_tostring(L, -1),
		                         port, NET_TCP|NET_UDP);
		if (ret != 0) {
			format_error(L, kr_strerror(ret));
			lua_error(L);
		}
		lua_pop(L, 1);
	}

	lua_pushboolean(L, true);
	return 1;
}

/** Listen on endpoint. */
static int net_listen(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	int port = KR_DNS_PORT;
	if (n > 1 && lua_isnumber(L, 2)) {
		port = lua_tointeger(L, 2);
	}

	/* Process interface or (address, port) pair. */
	if (lua_istable(L, 1)) {
		return net_listen_iface(L, port);
	} else if (n < 1 || !lua_isstring(L, 1)) {
		format_error(L, "expected 'listen(string addr, number port = 53)'");
		lua_error(L);
	}

	/* Open resolution context cache */
	struct engine *engine = engine_luaget(L);
	int ret = network_listen(&engine->net, lua_tostring(L, 1), port, NET_TCP|NET_UDP);
	if (ret != 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}

	lua_pushboolean(L, true);
	return 1;
}

/** Close endpoint. */
static int net_close(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2) {
		format_error(L, "expected 'close(string addr, number port)'");
		lua_error(L);
	}

	/* Open resolution context cache */
	struct engine *engine = engine_luaget(L);
	int ret = network_close(&engine->net, lua_tostring(L, 1), lua_tointeger(L, 2));
	lua_pushboolean(L, ret == 0);
	return 1;
}

/** List available interfaces. */
static int net_interfaces(lua_State *L)
{
	/* Retrieve interface list */
	int count = 0;
	char buf[INET6_ADDRSTRLEN]; /* http://tools.ietf.org/html/rfc4291 */
	uv_interface_address_t *info = NULL;
	uv_interface_addresses(&info, &count);
	lua_newtable(L);
	for (int i = 0; i < count; ++i) {
		uv_interface_address_t iface = info[i];
		lua_getfield(L, -1, iface.name);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			lua_newtable(L);
		}

		/* Address */
		lua_getfield(L, -1, "addr");
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			lua_newtable(L);
		}
		if (iface.address.address4.sin_family == AF_INET) {
			uv_ip4_name(&iface.address.address4, buf, sizeof(buf));
		} else if (iface.address.address4.sin_family == AF_INET6) {
			uv_ip6_name(&iface.address.address6, buf, sizeof(buf));
		} else {
			buf[0] = '\0';
		}
		lua_pushstring(L, buf);
		lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
		lua_setfield(L, -2, "addr");

		/* Hardware address. */
		char *p = buf;
		memset(buf, 0, sizeof(buf));
		for (unsigned k = 0; k < sizeof(iface.phys_addr); ++k) {
			sprintf(p, "%.2x:", iface.phys_addr[k] & 0xff);
			p += 3;
		}
		*(p - 1) = '\0';
		lua_pushstring(L, buf);
		lua_setfield(L, -2, "mac");

		/* Push table */
		lua_setfield(L, -2, iface.name);
	}
	uv_free_interface_addresses(info, count);

	return 1;
}

/** Set UDP maximum payload size. */
static int net_bufsize(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	knot_rrset_t *opt_rr = engine->resolver.opt_rr;
	if (!lua_isnumber(L, 1)) {
		lua_pushnumber(L, knot_edns_get_payload(opt_rr));
		return 1;
	}
	int bufsize = lua_tointeger(L, 1);
	if (bufsize < KNOT_EDNS_MIN_DNSSEC_PAYLOAD || bufsize > UINT16_MAX) {
		format_error(L, "bufsize must be within <1220, 65535>");
		lua_error(L);
	}
	knot_edns_set_payload(opt_rr, (uint16_t) bufsize);
	return 0;
}

int lib_net(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",       net_list },
		{ "listen",     net_listen },
		{ "close",      net_close },
		{ "interfaces", net_interfaces },
		{ "bufsize",    net_bufsize },
		{ NULL, NULL }
	};
	register_lib(L, "net", lib);
	return 1;
}

/** Return available cached backends. */
static int cache_backends(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	storage_registry_t *registry = &engine->storage_registry;

	lua_newtable(L);
	for (unsigned i = 0; i < registry->len; ++i) {
		struct storage_api *storage = &registry->at[i];
		lua_pushboolean(L, storage->api() == engine->resolver.cache.api);
		lua_setfield(L, -2, storage->prefix);
	}
	return 1;
}

/** Return number of cached records. */
static int cache_count(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	const namedb_api_t *storage = engine->resolver.cache.api;

	/* Fetch item count */
	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(&engine->resolver.cache, &txn, NAMEDB_RDONLY);
	if (ret != 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}

	/* First key is a version counter, omit it. */
	lua_pushinteger(L, storage->count(&txn.t) - 1);
	kr_cache_txn_abort(&txn);
	return 1;
}

/** Return cache statistics. */
static int cache_stats(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;
	lua_newtable(L);
	lua_pushnumber(L, cache->stats.hit);
	lua_setfield(L, -2, "hit");
	lua_pushnumber(L, cache->stats.miss);
	lua_setfield(L, -2, "miss");
	lua_pushnumber(L, cache->stats.insert);
	lua_setfield(L, -2, "insert");
	lua_pushnumber(L, cache->stats.delete);
	lua_setfield(L, -2, "delete");
	lua_pushnumber(L, cache->stats.txn_read);
	lua_setfield(L, -2, "txn_read");
	lua_pushnumber(L, cache->stats.txn_write);
	lua_setfield(L, -2, "txn_write");
	return 1;
}

static struct storage_api *cache_select_storage(struct engine *engine, const char **conf)
{
	/* Return default backend */
	storage_registry_t *registry = &engine->storage_registry;
	if (!*conf || !strstr(*conf, "://")) {
		return &registry->at[0];
	}

	/* Find storage backend from config prefix */
	for (unsigned i = 0; i < registry->len; ++i) {
		struct storage_api *storage = &registry->at[i];
		if (strncmp(*conf, storage->prefix, strlen(storage->prefix)) == 0) {
			*conf += strlen(storage->prefix);
			return storage;
		}
	}

	return NULL;
}

/** Open cache */
static int cache_open(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isnumber(L, 1)) {
		format_error(L, "expected 'open(number max_size, string config = \"\")'");
		lua_error(L);
	}

	/* Select cache storage backend */
	struct engine *engine = engine_luaget(L);
	unsigned cache_size = lua_tonumber(L, 1);
	const char *conf = n > 1 ? lua_tostring(L, 2) : NULL;
	const char *uri = conf;
	struct storage_api *storage = cache_select_storage(engine, &conf);
	if (!storage) {
		format_error(L, "unsupported cache backend");
		lua_error(L);
	}

	/* Close if already open */
	kr_cache_close(&engine->resolver.cache);

	/* Reopen cache */
	void *storage_opts = storage->opts_create(conf, cache_size);
	int ret = kr_cache_open(&engine->resolver.cache, storage->api(), storage_opts, engine->pool);
	free(storage_opts);
	if (ret != 0) {
		format_error(L, "can't open cache");
		lua_error(L);
	}

	/* Store current configuration */
	lua_getglobal(L, "cache");
	lua_pushstring(L, "current_size");
	lua_pushnumber(L, cache_size);
	lua_rawset(L, -3);
	lua_pushstring(L, "current_storage");
	lua_pushstring(L, uri);
	lua_rawset(L, -3);
	lua_pop(L, 1);

	lua_pushboolean(L, 1);
	return 1;
}

static int cache_close(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	kr_cache_close(&engine->resolver.cache);
	lua_getglobal(L, "cache");
	lua_pushstring(L, "current_size");
	lua_pushnumber(L, 0);
	lua_rawset(L, -3);
	lua_pop(L, 1);
	lua_pushboolean(L, 1);
	return 1;
}

int lib_cache(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "backends", cache_backends },
		{ "count",  cache_count },
		{ "stats",  cache_stats },
		{ "open",   cache_open },
		{ "close",  cache_close },
		{ NULL, NULL }
	};

	register_lib(L, "cache", lib);
	return 1;
}

static void event_free(uv_timer_t *timer)
{
	struct worker_ctx *worker = timer->loop->data;
	lua_State *L = worker->engine->L;
	int ref = (intptr_t) timer->data;
	luaL_unref(L, LUA_REGISTRYINDEX, ref);
	free(timer);
}

static int execute_callback(lua_State *L, int argc)
{
	int ret = engine_pcall(L, argc);
	if (ret != 0) {
		fprintf(stderr, "error: %s\n", lua_tostring(L, -1));
	}
	/* Clear the stack, there may be event a/o enything returned */
	lua_settop(L, 0);
	lua_gc(L, LUA_GCCOLLECT, 0);
	return ret;
}

static void event_callback(uv_timer_t *timer)
{
	struct worker_ctx *worker = timer->loop->data;
	lua_State *L = worker->engine->L;

	/* Retrieve callback and execute */
	lua_rawgeti(L, LUA_REGISTRYINDEX, (intptr_t) timer->data);
	lua_rawgeti(L, -1, 1);
	lua_pushinteger(L, (intptr_t) timer->data);
	int ret = execute_callback(L, 1);
	/* Free callback if not recurrent or an error */
	if (ret != 0 || uv_timer_get_repeat(timer) == 0) {
		if (!uv_is_closing((uv_handle_t *)timer)) {
			uv_close((uv_handle_t *)timer, (uv_close_cb) event_free);
		}
	}
}

static int event_sched(lua_State *L, unsigned timeout, unsigned repeat)
{
	uv_timer_t *timer = malloc(sizeof(*timer));
	if (!timer) {
		format_error(L, "out of memory");
		lua_error(L);
	}

	/* Start timer with the reference */
	uv_loop_t *loop = uv_default_loop();
	uv_timer_init(loop, timer);
	int ret = uv_timer_start(timer, event_callback, timeout, repeat);
	if (ret != 0) {
		free(timer);
		format_error(L, "couldn't start the event");
		lua_error(L);
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushlightuserdata(L, timer);
	lua_rawseti(L, -2, 2);
	int ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Save reference to the timer */
	timer->data = (void *) (intptr_t)ref;
	lua_pushinteger(L, ref);
	return 1;
}

static int event_after(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'after(number timeout, function)'");
		lua_error(L);
	}

	return event_sched(L, lua_tonumber(L, 1), 0);
}

static int event_recurrent(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'recurrent(number interval, function)'");
		lua_error(L);
	}
	return event_sched(L, 0, lua_tonumber(L, 1));
}

static int event_cancel(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 1 || !lua_isnumber(L, 1)) {
		format_error(L, "expected 'cancel(number event)'");
		lua_error(L);
	}

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, false);
		return 1;
	}

	/* Close the timer */
	lua_rawgeti(L, -1, 2);
	uv_handle_t *timer = lua_touserdata(L, -1);
	if (!uv_is_closing(timer)) {
		uv_close(timer, (uv_close_cb) event_free);
	}
	lua_pushboolean(L, true);
	return 1;
}

int lib_event(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "after",      event_after },
		{ "recurrent",  event_recurrent },
		{ "cancel",     event_cancel },
		{ NULL, NULL }
	};

	register_lib(L, "event", lib);
	return 1;
}

static inline struct worker_ctx *wrk_luaget(lua_State *L) {
	lua_getglobal(L, "__worker");
	struct worker_ctx *worker = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return worker;
}

/* @internal Call the Lua callback stored in baton. */
static void resolve_callback(struct worker_ctx *worker, struct kr_request *req, void *baton)
{
	assert(worker);
	assert(req);
	assert(baton);
	lua_State *L = worker->engine->L;
	intptr_t cb_ref = (intptr_t) baton;
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb_ref);
	lua_pushlightuserdata(L, req->answer);
	(void) execute_callback(L, 1);
}

static int wrk_resolve(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}
	/* Create query packet */
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_EDNS_MAX_UDP_PAYLOAD, NULL);
	if (!pkt) {
		lua_pushstring(L, strerror(ENOMEM));
		lua_error(L);
	}
	uint8_t dname[KNOT_DNAME_MAXLEN];
	knot_dname_from_str(dname, lua_tostring(L, 1), sizeof(dname));
	/* Check class and type */
	uint16_t rrtype = lua_tointeger(L, 2);
	if (!lua_isnumber(L, 2)) {
		lua_pushstring(L, "invalid RR type");
		lua_error(L);
	}
	uint16_t rrclass = lua_tointeger(L, 3);
	if (!lua_isnumber(L, 3)) { /* Default class is IN */
		rrclass = KNOT_CLASS_IN;
	}
	knot_pkt_put_question(pkt, dname, rrclass, rrtype);
	knot_wire_set_rd(pkt->wire);
	/* Add OPT RR */
	pkt->opt_rr = knot_rrset_copy(worker->engine->resolver.opt_rr, NULL);
	if (!pkt->opt_rr) {
		return kr_error(ENOMEM);
	}	
	/* Add completion callback */
	int ret = 0;
	unsigned options = lua_tointeger(L, 4);
	if (lua_isfunction(L, 5)) {
		/* Store callback in registry */
		lua_pushvalue(L, 5);
		int cb = luaL_ref(L, LUA_REGISTRYINDEX);
		ret = worker_resolve(worker, pkt, options, resolve_callback, (void *) (intptr_t)cb);
	} else {
		ret = worker_resolve(worker, pkt, options, NULL, NULL);
	}
	
	knot_rrset_free(&pkt->opt_rr, NULL);
	knot_pkt_free(&pkt);
	lua_pushboolean(L, ret == 0);
	return 1;
}

/** Return worker statistics. */
static int wrk_stats(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}
	lua_newtable(L);
	lua_pushnumber(L, worker->stats.concurrent);
	lua_setfield(L, -2, "concurrent");
	lua_pushnumber(L, worker->stats.udp);
	lua_setfield(L, -2, "udp");
	lua_pushnumber(L, worker->stats.tcp);
	lua_setfield(L, -2, "tcp");
	lua_pushnumber(L, worker->stats.ipv6);
	lua_setfield(L, -2, "ipv6");
	lua_pushnumber(L, worker->stats.ipv4);
	lua_setfield(L, -2, "ipv4");
	lua_pushnumber(L, worker->stats.queries);
	lua_setfield(L, -2, "queries");
	lua_pushnumber(L, worker->stats.dropped);
	lua_setfield(L, -2, "dropped");
	lua_pushnumber(L, worker->stats.timeout);
	lua_setfield(L, -2, "timeout");
	return 1;
}

int lib_worker(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "resolve",  wrk_resolve },
		{ "stats",    wrk_stats },
		{ NULL, NULL }
	};
	register_lib(L, "worker", lib);
	return 1;
}
