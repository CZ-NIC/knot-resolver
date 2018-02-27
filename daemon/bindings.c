/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdint.h>
#include <uv.h>
#include <contrib/cleanup.h>
#include <libknot/descriptor.h>

#include "lib/cache/api.h"
#include "lib/cache/cdb_api.h"
#include "lib/utils.h"
#include "daemon/bindings.h"
#include "daemon/worker.h"
#include "daemon/tls.h"
#include "daemon/zimport.h"

#define xstr(s) str(s)
#define str(s) #s

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

static inline struct worker_ctx *wrk_luaget(lua_State *L) {
	lua_getglobal(L, "__worker");
	struct worker_ctx *worker = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return worker;
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
	char *declaration = strdup(lua_tostring(L, 1));
	if (!declaration) {
		return kr_error(ENOMEM);
	}
	const char *name = strtok(declaration, " ");
	const char *precedence = strtok(NULL, " ");
	const char *ref = strtok(NULL, " ");
	/* Load engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_register(engine, name, precedence, ref);
	free(declaration);
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
		lua_pushboolean(L, ep->flags & NET_TLS);
		lua_setfield(L, -2, "tls");
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

/** Listen on an address list represented by the top of lua stack. */
static int net_listen_addrs(lua_State *L, int port, int flags)
{
	/* Case: table with 'addr' field; only follow that field directly. */
	lua_getfield(L, -1, "addr");
	if (!lua_isnil(L, -1)) {
		lua_replace(L, -2);
	} else {
		lua_pop(L, 1);
	}

	/* Case: string, representing a single address. */
	const char *str = lua_tostring(L, -1);
	if (str != NULL) {
		struct engine *engine = engine_luaget(L);
		int ret = network_listen(&engine->net, str, port, flags);
		if (ret != 0) {
			kr_log_info("[system] bind to '%s@%d' %s\n",
					str, port, kr_strerror(ret));
		}
		return ret == 0;
	}

	/* Last case: table where all entries are added recursively. */
	if (!lua_istable(L, -1)) {
		format_error(L, "bad type for address");
		lua_error(L);
		return 0;
	}
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (net_listen_addrs(L, port, flags) == 0)
			return 0;
		lua_pop(L, 1);
	}
	return 1;
}

static bool table_get_flag(lua_State *L, int index, const char *key, bool def)
{
	bool result = def;
	lua_getfield(L, index, key);
	if (lua_isboolean(L, -1)) {
		result = lua_toboolean(L, -1);
	}
	lua_pop(L, 1);
	return result;
}

/** Listen on endpoint. */
static int net_listen(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || n > 3) {
		format_error(L, "expected one to three arguments; usage:\n"
			     "net.listen(addressses, [port = " xstr(KR_DNS_PORT) ", flags = {tls = (port == " xstr(KR_DNS_TLS_PORT) ")}])\n");
		lua_error(L);
	}

	int port = KR_DNS_PORT;
	if (n > 1 && lua_isnumber(L, 2)) {
		port = lua_tointeger(L, 2);
	}

	bool tls = (port == KR_DNS_TLS_PORT);
	if (n > 2 && lua_istable(L, 3)) {
		tls = table_get_flag(L, 3, "tls", tls);
	}
	int flags = tls ? (NET_TCP|NET_TLS) : (NET_TCP|NET_UDP);
	
	/* Now focus on the first argument. */
	lua_pop(L, n - 1);
	int res = net_listen_addrs(L, port, flags);
	lua_pushboolean(L, res);
	return res;
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
	char buf[INET6_ADDRSTRLEN]; /* https://tools.ietf.org/html/rfc4291 */
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
			sprintf(p, "%s%.2x", k > 0 ? ":" : "", iface.phys_addr[k] & 0xff);
			p += 3;
		}
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
	if (bufsize < 512 || bufsize > UINT16_MAX) {
		format_error(L, "bufsize must be within <512, " xstr(UINT16_MAX) ">");
		lua_error(L);
	}
	knot_edns_set_payload(opt_rr, (uint16_t) bufsize);
	return 0;
}

/** Set TCP pipelining size. */
static int net_pipeline(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}
	if (!lua_isnumber(L, 1)) {
		lua_pushnumber(L, worker->tcp_pipeline_max);
		return 1;
	}
	int len = lua_tointeger(L, 1);
	if (len < 0 || len > UINT16_MAX) {
		format_error(L, "tcp_pipeline must be within <0, " xstr(UINT16_MAX) ">");
		lua_error(L);
	}
	worker->tcp_pipeline_max = len;
	lua_pushnumber(L, len);
	return 1;
}

static int net_tls(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct network *net = &engine->net;
	if (!net) {
		return 0;
	}

	/* Only return current credentials. */
	if (lua_gettop(L) == 0) {
		/* No credentials configured yet. */
		if (!net->tls_credentials) {
			return 0;
		}
		lua_newtable(L);
		lua_pushstring(L, net->tls_credentials->tls_cert);
		lua_setfield(L, -2, "cert_file");
		lua_pushstring(L, net->tls_credentials->tls_key);
		lua_setfield(L, -2, "key_file");
		return 1;
	}

	if ((lua_gettop(L) != 2) || !lua_isstring(L, 1) || !lua_isstring(L, 2)) {
		lua_pushstring(L, "net.tls takes two parameters: (\"cert_file\", \"key_file\")");
		lua_error(L);
	}

	int r = tls_certificate_set(net, lua_tostring(L, 1), lua_tostring(L, 2));
	if (r != 0) {
		lua_pushstring(L, kr_strerror(r));
		lua_error(L);
	}

	lua_pushboolean(L, true);
	return 1;
}

static int print_tls_param(const char *key, void *val, void *data)
{
	if (!val) {
		return 0;
	}

	struct tls_client_paramlist_entry *entry = (struct tls_client_paramlist_entry *)val;

	lua_State *L = (lua_State *)data;

	lua_createtable(L, 0, 3);

	lua_createtable(L, entry->pins.len, 0);
	for (size_t i = 0; i < entry->pins.len; ++i) {
		lua_pushnumber(L, i + 1);
		lua_pushstring(L, entry->pins.at[i]);
		lua_settable(L, -3);
	}
	lua_setfield(L, -2, "pins");

	lua_createtable(L, entry->ca_files.len, 0);
	for (size_t i = 0; i < entry->ca_files.len; ++i) {
		lua_pushnumber(L, i + 1);
		lua_pushstring(L, entry->ca_files.at[i]);
		lua_settable(L, -3);
	}
	lua_setfield(L, -2, "ca_files");

	lua_createtable(L, entry->hostnames.len, 0);
	for (size_t i = 0; i < entry->hostnames.len; ++i) {
		lua_pushnumber(L, i + 1);
		lua_pushstring(L, entry->hostnames.at[i]);
		lua_settable(L, -3);
	}
	lua_setfield(L, -2, "hostnames");

	lua_setfield(L, -2, key);

	return 0;
}

static int print_tls_client_params(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct network *net = &engine->net;
	if (!net) {
		return 0;
	}
	if (net->tls_client_params.root == 0 ) {
		return 0;
	}
	lua_newtable(L);
	map_walk(&net->tls_client_params, print_tls_param, (void *)L);
	return 1;
}


static int net_tls_client(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct network *net = &engine->net;
	if (!net) {
		return 0;
	}

	/* Only return current credentials. */
	if (lua_gettop(L) == 0) {
		return print_tls_client_params(L);
	}

	const char *full_addr = NULL;
	bool pin_exists = false;
	bool ca_file_exists = false;
	if ((lua_gettop(L) == 1) && lua_isstring(L, 1)) {
		full_addr = lua_tostring(L, 1);
	} else if ((lua_gettop(L) == 2) && lua_isstring(L, 1) && lua_istable(L, 2)) {
		full_addr = lua_tostring(L, 1);
		pin_exists = true;
	} else if ((lua_gettop(L) == 3) && lua_isstring(L, 1) && lua_istable(L, 2)) {
		full_addr = lua_tostring(L, 1);
		ca_file_exists = true;
	} else if ((lua_gettop(L) == 4) && lua_isstring(L, 1) &&
		    lua_istable(L, 2) && lua_istable(L, 3)) {
		full_addr = lua_tostring(L, 1);
		pin_exists = true;
		ca_file_exists = true;
	} else {
		format_error(L, "net.tls_client takes one parameter (\"address\"), two parameters (\"address\",\"pin\"), three parameters (\"address\", \"ca_file\", \"hostname\") or four ones: (\"address\", \"pin\", \"ca_file\", \"hostname\")");
		lua_error(L);
	}

	char addr[INET6_ADDRSTRLEN];
	uint16_t port = 0;
	if (kr_straddr_split(full_addr, addr, sizeof(addr), &port) != kr_ok()) {
		format_error(L, "invalid IP address");
		lua_error(L);
	}

	if (port == 0) {
		port = 853;
	}

	if (!pin_exists && !ca_file_exists) {
		int r = tls_client_params_set(&net->tls_client_params,
					      addr, port, NULL, NULL, NULL);
		if (r != 0) {
			lua_pushstring(L, kr_strerror(r));
			lua_error(L);
		}

		lua_pushboolean(L, true);
		return 1;
	}

	if (pin_exists) {
		/* iterate over table with pins
		 * http://www.lua.org/manual/5.1/manual.html#lua_next */
		lua_pushnil(L); /* first key */
		while (lua_next(L, 2)) {  /* pin table is in stack at index 2 */
			/* pin now at index -1, key at index -2*/
			const char *pin = lua_tostring(L, -1);
			int r = tls_client_params_set(&net->tls_client_params,
						      addr, port, NULL, NULL, pin);
			if (r != 0) {
				lua_pushstring(L, kr_strerror(r));
				lua_error(L);
			}
			lua_pop(L, 1);
		}
	}

	int ca_table_index = 2;
	int hostname_table_index = 3;
	if (ca_file_exists) {
		if (pin_exists) {
			ca_table_index = 3;
			hostname_table_index = 4;
		}
	} else {
		lua_pushboolean(L, true);
		return 1;
	}

	/* iterate over ca filenames */
	lua_pushnil(L);
	while (lua_next(L, ca_table_index)) {
		const char *ca_file = lua_tostring(L, -1);
		int r = tls_client_params_set(&net->tls_client_params,
					      addr, port, ca_file, NULL, NULL);
		if (r != 0) {
			lua_pushstring(L, kr_strerror(r));
			lua_error(L);
		}
		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	/* iterate over hostnames */
	lua_pushnil(L);
	while (lua_next(L, hostname_table_index)) {
		const char *hostname = lua_tostring(L, -1);
		int r = tls_client_params_set(&net->tls_client_params,
					      addr, port, NULL, hostname, NULL);
		if (r != 0) {
			lua_pushstring(L, kr_strerror(r));
			lua_error(L);
		}
		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	lua_pushboolean(L, true);
	return 1;
}

static int net_tls_padding(lua_State *L)
{
	struct engine *engine = engine_luaget(L);

	/* Only return current padding. */
	if (lua_gettop(L) == 0) {
		if (engine->resolver.tls_padding < 0) {
			lua_pushboolean(L, true);
			return 1;
		} else if (engine->resolver.tls_padding == 0) {
			lua_pushboolean(L, false);
			return 1;
		}
		lua_pushinteger(L, engine->resolver.tls_padding);
		return 1;
	}

	if ((lua_gettop(L) != 1)) {
		lua_pushstring(L, "net.tls_padding takes one parameter: (\"padding\")");
		lua_error(L);
	}
	if (lua_isboolean(L, 1)) {
		bool x = lua_toboolean(L, 1);
		if (x) {
			engine->resolver.tls_padding = -1;
		} else {
			engine->resolver.tls_padding = 0;
		}
	} else if (lua_isnumber(L, 1)) {
		int padding = lua_tointeger(L, 1);
		if ((padding < 0) || (padding > MAX_TLS_PADDING)) {
			lua_pushstring(L, "net.tls_padding parameter has to be true, false, or a number between <0, " xstr(MAX_TLS_PADDING) ">");
			lua_error(L);
		}
		engine->resolver.tls_padding = padding;
	} else {
		lua_pushstring(L, "net.tls_padding parameter has to be true, false, or a number between <0, " xstr(MAX_TLS_PADDING) ">");
		lua_error(L);
	}
	lua_pushboolean(L, true);
	return 1;
}

static int net_outgoing(lua_State *L, int family)
{
	struct worker_ctx *worker = wrk_luaget(L);
	union inaddr *addr;
	if (family == AF_INET)
		addr = (union inaddr*)&worker->out_addr4;
	else
		addr = (union inaddr*)&worker->out_addr6;

	if (lua_gettop(L) == 0) { /* Return the current value. */
		if (addr->ip.sa_family == AF_UNSPEC) {
			lua_pushnil(L);
			return 1;
		}
		if (addr->ip.sa_family != family) {
			assert(false);
			lua_error(L);
		}
		char addr_buf[INET6_ADDRSTRLEN];
		int err;
		if (family == AF_INET)
			err = uv_ip4_name(&addr->ip4, addr_buf, sizeof(addr_buf));
		else
			err = uv_ip6_name(&addr->ip6, addr_buf, sizeof(addr_buf));
		if (err)
			lua_error(L);
		lua_pushstring(L, addr_buf);
		return 1;
	}

	if ((lua_gettop(L) != 1) || (!lua_isstring(L, 1) && !lua_isnil(L, 1))) {
		format_error(L, "net.outgoing_vX takes one address string parameter or nil");
		lua_error(L);
	}

	if (lua_isnil(L, 1)) {
		addr->ip.sa_family = AF_UNSPEC;
		return 1;
	}

	const char *addr_str = lua_tostring(L, 1);
	int err;
	if (family == AF_INET)
		err = uv_ip4_addr(addr_str, 0, &addr->ip4);
	else
		err = uv_ip6_addr(addr_str, 0, &addr->ip6);
	if (err) {
		format_error(L, "net.outgoing_vX: failed to parse the address");
		lua_error(L);
	}
	lua_pushboolean(L, true);
	return 1;
}

static int net_outgoing_v4(lua_State *L) { return net_outgoing(L, AF_INET); }
static int net_outgoing_v6(lua_State *L) { return net_outgoing(L, AF_INET6); }

int lib_net(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",         net_list },
		{ "listen",       net_listen },
		{ "close",        net_close },
		{ "interfaces",   net_interfaces },
		{ "bufsize",      net_bufsize },
		{ "tcp_pipeline", net_pipeline },
		{ "tls",          net_tls },
		{ "tls_server",   net_tls },
		{ "tls_client",   net_tls_client },
		{ "tls_padding",  net_tls_padding },
		{ "outgoing_v4",  net_outgoing_v4 },
		{ "outgoing_v6",  net_outgoing_v6 },
		{ NULL, NULL }
	};
	register_lib(L, "net", lib);
	return 1;
}

/** Return available cached backends. */
static int cache_backends(lua_State *L)
{
	struct engine *engine = engine_luaget(L);

	lua_newtable(L);
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		lua_pushboolean(L, api == engine->resolver.cache.api);
		lua_setfield(L, -2, api->name);
	}
	return 1;
}

/** Return number of cached records. */
static int cache_count(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	const struct kr_cdb_api *api = engine->resolver.cache.api;

	struct kr_cache *cache = &engine->resolver.cache;
	int count = api->count(cache->db);
	if (kr_cache_is_open(cache) && count >= 0) {
		/* First key is a version counter, omit it if nonempty. */
		lua_pushinteger(L, count ? count - 1 : 0);
		return 1;
	}
	return 0;
}

/** Return time of last checkpoint, or re-set it if passed `true`. */
static int cache_checkpoint(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;

	if (lua_gettop(L) == 0) { /* Return the current value. */
		lua_newtable(L);
		lua_pushnumber(L, cache->checkpoint_monotime);
		lua_setfield(L, -2, "monotime");
		lua_newtable(L);
		lua_pushnumber(L, cache->checkpoint_walltime.tv_sec);
		lua_setfield(L, -2, "sec");
		lua_pushnumber(L, cache->checkpoint_walltime.tv_usec);
		lua_setfield(L, -2, "usec");
		lua_setfield(L, -2, "walltime");
		return 1;
	}

	if (lua_gettop(L) != 1 || !lua_isboolean(L, 1) || !lua_toboolean(L, 1)) {
		format_error(L, "cache.checkpoint() takes no parameters or a true value");
		lua_error(L);
	}
	kr_cache_make_checkpoint(cache);
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
	return 1;
}

static const struct kr_cdb_api *cache_select(struct engine *engine, const char **conf)
{
	/* Return default backend */
	if (*conf == NULL || !strstr(*conf, "://")) {
		return engine->backends.at[0];
	}

	/* Find storage backend from config prefix */
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		if (strncmp(*conf, api->name, strlen(api->name)) == 0) {
			*conf += strlen(api->name) + strlen("://");
			return api;
		}
	}

	return NULL;
}

static int cache_max_ttl(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;

	int n = lua_gettop(L);
	if (n > 0) {
		if (!lua_isnumber(L, 1)) {
			format_error(L, "expected 'max_ttl(number ttl)'");
			lua_error(L);
		}
		uint32_t min = cache->ttl_min;
		int64_t ttl = lua_tonumber(L, 1);
		if (ttl < 0 || ttl <= min || ttl > UINT32_MAX) {
			format_error(L, "max_ttl must be larger than minimum TTL, and in range <1, " xstr(UINT32_MAX) ">'");
			lua_error(L);
		}
		cache->ttl_max = ttl;
	}
	lua_pushinteger(L, cache->ttl_max);
	return 1;
}


static int cache_min_ttl(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;

	int n = lua_gettop(L);
	if (n > 0) {
		if (!lua_isnumber(L, 1)) {
			format_error(L, "expected 'min_ttl(number ttl)'");
			lua_error(L);
		}
		uint32_t max = cache->ttl_max;
		int64_t ttl = lua_tonumber(L, 1);
		if (ttl < 0 || ttl >= max || ttl > UINT32_MAX) {
			format_error(L, "min_ttl must be smaller than maximum TTL, and in range <0, " xstr(UINT32_MAX) ">'");
			lua_error(L);
		}
		cache->ttl_min = ttl;
	}
	lua_pushinteger(L, cache->ttl_min);
	return 1;
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

	lua_Number csize_lua = lua_tonumber(L, 1);
	if (!(csize_lua >= 8192 && csize_lua < SIZE_MAX)) { /* min. is basically arbitrary */
		format_error(L, "invalid cache size specified, it must be in range <8192, " xstr(SIZE_MAX)  ">");
		lua_error(L);
	}
	size_t cache_size = csize_lua;

	const char *conf = n > 1 ? lua_tostring(L, 2) : NULL;
	const char *uri = conf;
	const struct kr_cdb_api *api = cache_select(engine, &conf);
	if (!api) {
		format_error(L, "unsupported cache backend");
		lua_error(L);
	}

	/* Close if already open */
	kr_cache_close(&engine->resolver.cache);

	/* Reopen cache */
	struct kr_cdb_opts opts = {
		(conf && strlen(conf)) ? conf : ".",
		cache_size
	};
	int ret = kr_cache_open(&engine->resolver.cache, api, &opts, engine->pool);
	if (ret != 0) {
		char cwd[PATH_MAX];
		if(getcwd(cwd, sizeof(cwd)) == NULL) {
			const char errprefix[] = "<invalid working directory>";
			strncpy(cwd, errprefix, sizeof(cwd));
		}
		return luaL_error(L, "can't open cache path '%s'; working directory '%s'", opts.path, cwd);
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
	struct kr_cache *cache = &engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	kr_cache_close(cache);
	lua_getglobal(L, "cache");
	lua_pushstring(L, "current_size");
	lua_pushnumber(L, 0);
	lua_rawset(L, -3);
	lua_pop(L, 1);
	lua_pushboolean(L, 1);
	return 1;
}

#if 0
/** @internal Prefix walk. */
static int cache_prefixed(struct kr_cache *cache, const char *args, knot_db_val_t *results, int maxresults)
{
	/* Decode parameters */
	uint8_t namespace = 'R';
	char *extra = strchr(args, ' ');
	if (extra != NULL) {
		extra[0] = '\0';
		namespace = extra[1];
	}

	/* Convert to domain name */
	uint8_t buf[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(buf, args, sizeof(buf))) {
		return kr_error(EINVAL);
	}

	/* Start prefix search */
	int ret = kr_cache_match(cache, namespace, buf, results, maxresults);
	kr_cache_sync(cache);
	return ret;
}

/** @internal Delete iterated key. */
static int cache_remove_prefix(struct kr_cache *cache, const char *args)
{
	/* Check if we can remove */
	if (!cache || !cache->api || !cache->api->remove) {
		return kr_error(ENOSYS);
	}
	static knot_db_val_t result_set[1000];
	int ret = cache_prefixed(cache, args, result_set, 1000);
	if (ret < 0) {
		return ret;
	}
	/* Duplicate result set as we're going to remove it
	 * which will invalidate result set. */
	for (int i = 0; i < ret; ++i) {
		void *dst = malloc(result_set[i].len);
		if (!dst) {
			return kr_error(ENOMEM);
		}
		memcpy(dst, result_set[i].data, result_set[i].len);
		result_set[i].data = dst;
	}
	cache->api->remove(cache->db, result_set, ret);
	kr_cache_sync(cache);
	/* Free keys */
	for (int i = 0; i < ret; ++i) {
		free(result_set[i].data);
	}
	return ret;
}
#endif

/** Prune expired/invalid records. */
static int cache_prune(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	/* Check parameters */
	int prune_max = UINT16_MAX;
	int n = lua_gettop(L);
	if (n >= 1 && lua_isnumber(L, 1)) {
		prune_max = lua_tointeger(L, 1);
	}

	/* Check if API supports pruning. */
	int ret = kr_error(ENOSYS);
	if (cache->api->prune) {
		ret = cache->api->prune(cache->db, prune_max);
	}
	/* Commit and format result. */
	if (ret < 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}
	lua_pushinteger(L, ret);
	return 1;
}

/** Clear all records. */
static int cache_clear(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	/* Check parameters */
	const char *args = NULL;
	int n = lua_gettop(L);
	if (n >= 1 && lua_isstring(L, 1)) {
		args = lua_tostring(L, 1);
	}

	/* Clear a sub-tree in cache. */
	if (args && strlen(args) > 0) {
		int ret = kr_error(ENOSYS); // FIXME cache_remove_prefix(cache, args);
		if (ret < 0) {
			format_error(L, kr_strerror(ret));
			lua_error(L);
		}
		lua_pushinteger(L, ret);
		return 1;
	}

	/* Clear cache. */
	int ret = kr_cache_clear(cache);
	if (ret < 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}

	/* Clear reputation tables */
	lru_reset(engine->resolver.cache_rtt);
	lru_reset(engine->resolver.cache_rep);
	lru_reset(engine->resolver.cache_cookie);
	lua_pushboolean(L, true);
	return 1;
}

/** @internal Dump cache key into table on Lua stack. */
static void cache_dump_key(lua_State *L, knot_db_val_t *key)
{
	char buf[KNOT_DNAME_MAXLEN];
	/* Extract type */
	uint16_t type = 0;
	const char *endp = (const char *)key->data + key->len - sizeof(uint16_t);
	memcpy(&type, endp, sizeof(uint16_t));
	endp -= 1;
	/* Extract domain name */
	char *dst = buf;
	const char *scan = endp - 1;
	while (scan > (const char *)key->data) {
		if (*scan == '\0') {
			const size_t lblen = endp - scan - 1;
			memcpy(dst, scan + 1, lblen);
			dst += lblen;
			*dst++ = '.';
			endp = scan;
		}
		--scan;
	}
	memcpy(dst, scan + 1, endp - scan);
	/* If name typemap doesn't exist yet, create it */
	lua_getfield(L, -1, buf);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		lua_newtable(L);
	}
	/* Append to typemap */
	char type_buf[16] = { '\0' };
	knot_rrtype_to_string(type, type_buf, sizeof(type_buf));
	lua_pushboolean(L, true);
	lua_setfield(L, -2, type_buf);
	/* Set name typemap */
	lua_setfield(L, -2, buf);
}

/** Query cached records. */
static int cache_get(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_cache *cache = &engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isstring(L, 1)) {
		format_error(L, "expected 'cache.get(string key)'");
		lua_error(L);
	}

	/* Retrieve set of keys */
	//const char *args = lua_tostring(L, 1);
	static knot_db_val_t result_set[100];
	int ret = kr_error(ENOSYS); // FIXME cache_prefixed(cache, args, result_set, 100);
	if (ret < 0) {
		format_error(L, kr_strerror(ret));
		lua_error(L);
	}
	/* Format output */
	lua_newtable(L);
	for (int i = 0; i < ret; ++i) {
		cache_dump_key(L, &result_set[i]);
	}
	return 1;
}

/** Set time interval for cleaning rtt cache.
 * Servers with score >= KR_NS_TIMEOUTED will be cleaned after
 * this interval ended up, so that they will be able to participate
 * in NS elections again. */
static int cache_ns_tout(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_context *ctx = &engine->resolver;

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1) {
		lua_pushinteger(L, ctx->cache_rtt_tout_retry_interval);
		return 1;
	}

	if (!lua_isnumber(L, 1)) {
		format_error(L, "expected 'cache.ns_tout(interval in ms)'");
		lua_error(L);
	}

	lua_Number interval_lua = lua_tonumber(L, 1);
	if (!(interval_lua >= 0 && interval_lua < UINT_MAX)) {
		format_error(L, "invalid interval specified, it must be in range > 0, < " xstr(UINT_MAX));
		lua_error(L);
	}

	ctx->cache_rtt_tout_retry_interval = interval_lua;
	lua_pushinteger(L, ctx->cache_rtt_tout_retry_interval);
	return 1;
}

/** Zone import completion callback.
 * Deallocates zone import context. */
static void cache_zone_import_cb(int state, void *param)
{
	assert (param);
	(void)state;
	struct worker_ctx *worker = (struct worker_ctx *)param;
	assert (worker->z_import);
	zi_free(worker->z_import);
	worker->z_import = NULL;
}

/** Import zone from file. */
static int cache_zone_import(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}

	if (worker->z_import && zi_import_started(worker->z_import)) {
		format_error(L, "import has already started");
		lua_error(L);
	}

	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct kr_cache *cache = &engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isstring(L, 1)) {
		format_error(L, "expected 'cache.zone_import(string key)'");
		lua_error(L);
	}

	/* Parse zone file */
	const char *zone_file = lua_tostring(L, 1);

	const char *default_origin = NULL; /* TODO */
	uint16_t default_rclass = 1;
	uint32_t default_ttl = 0;

	if (worker->z_import == NULL) {
		worker->z_import = zi_allocate(worker, cache_zone_import_cb, worker);
		if (worker->z_import == NULL) {
			format_error(L, "can't allocate zone import context");
			lua_error(L);
		}
	}

	int ret = zi_zone_import(worker->z_import, zone_file, default_origin,
				 default_rclass, default_ttl);

	if (ret != 0) {
		format_error(L, "error parsing zone file");
		lua_error(L);
	}

	lua_pushstring(L, "zone file successfully parsed, import started");
	return 1;
}

int lib_cache(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "backends", cache_backends },
		{ "count",  cache_count },
		{ "stats",  cache_stats },
		{ "checkpoint", cache_checkpoint },
		{ "open",   cache_open },
		{ "close",  cache_close },
		{ "prune",  cache_prune },
		{ "clear",  cache_clear },
		{ "get",    cache_get },
		{ "max_ttl", cache_max_ttl },
		{ "min_ttl", cache_min_ttl },
		{ "ns_tout", cache_ns_tout },
		{ "zone_import", cache_zone_import },
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
	if (ret != 0 || (uv_timer_get_repeat(timer) == 0 && uv_is_active((uv_handle_t *)timer) == 0)) {
		if (!uv_is_closing((uv_handle_t *)timer)) {
			uv_close((uv_handle_t *)timer, (uv_close_cb) event_free);
		}
	}
}

static void event_fdcallback(uv_poll_t* handle, int status, int events)
{
	struct worker_ctx *worker = handle->loop->data;
	lua_State *L = worker->engine->L;

	/* Retrieve callback and execute */
	lua_rawgeti(L, LUA_REGISTRYINDEX, (intptr_t) handle->data);
	lua_rawgeti(L, -1, 1);
	lua_pushinteger(L, (intptr_t) handle->data);
	lua_pushinteger(L, status);
	lua_pushinteger(L, events);
	int ret = execute_callback(L, 3);
	/* Free callback if not recurrent or an error */
	if (ret != 0) {
		if (!uv_is_closing((uv_handle_t *)handle)) {
			uv_close((uv_handle_t *)handle, (uv_close_cb) event_free);
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

static int event_reschedule(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isnumber(L, 2)) {
		format_error(L, "expected 'reschedule(number event, number timeout)'");
		lua_error(L);
	}

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, false);
		return 1;
	}

	/* Reschedule the timer */
	lua_rawgeti(L, -1, 2);
	uv_handle_t *timer = lua_touserdata(L, -1);
	if (!uv_is_closing(timer)) {
		if (uv_is_active(timer)) {
			uv_timer_stop((uv_timer_t *)timer);
		}
		int ret = uv_timer_start((uv_timer_t *)timer, event_callback, lua_tointeger(L, 2), 0);
		if (ret != 0) {
			event_cancel(L);
			lua_pushboolean(L, false);
			return 1;
		}
	}
	lua_pushboolean(L, true);
	return 1;
}

static int event_fdwatch(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'socket(number fd, function)'");
		lua_error(L);
	}

	uv_poll_t *handle = malloc(sizeof(*handle));
	if (!handle) {
		format_error(L, "out of memory");
		lua_error(L);
	}

	/* Start timer with the reference */
	int sock = lua_tonumber(L, 1);
	uv_loop_t *loop = uv_default_loop();
#if defined(__APPLE__) || defined(__FreeBSD__)
	/* libuv is buggy and fails to create poller for
	 * kqueue sockets as it can't be fcntl'd to non-blocking mode,
	 * so we pass it a copy of standard input and then
	 * switch it with real socket before starting the poller
	 */
	int decoy_fd = dup(STDIN_FILENO);
	int ret = uv_poll_init(loop, handle, decoy_fd);
	if (ret == 0) {
		handle->io_watcher.fd = sock;
	}
	close(decoy_fd);
#else
	int ret = uv_poll_init(loop, handle, sock);
#endif
	if (ret == 0) {
		ret = uv_poll_start(handle, UV_READABLE, event_fdcallback);
	}
	if (ret != 0) {
		free(handle);
		format_error(L, "couldn't start event poller");
		lua_error(L);
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushlightuserdata(L, handle);
	lua_rawseti(L, -2, 2);
	int ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Save reference to the timer */
	handle->data = (void *) (intptr_t)ref;
	lua_pushinteger(L, ref);
	return 1;
}

int lib_event(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "after",      event_after },
		{ "recurrent",  event_recurrent },
		{ "cancel",     event_cancel },
		{ "socket",     event_fdwatch },
		{ "reschedule", event_reschedule },
		{ NULL, NULL }
	};

	register_lib(L, "event", lib);
	return 1;
}

static int wrk_resolve(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}

	uint8_t dname[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(dname, lua_tostring(L, 1), sizeof(dname))) {
		lua_pushstring(L, "invalid qname");
		lua_error(L);
	};

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

	/* Add query options */
	const struct kr_qflags *options = lua_topointer(L, 4);
	if (!options) { /* but we rely on the lua wrapper when dereferencing non-NULL */
		lua_pushstring(L, "invalid options");
		lua_error(L);
	}

	/* Create query packet */
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_EDNS_MAX_UDP_PAYLOAD, NULL);
	if (!pkt) {
		lua_pushstring(L, kr_strerror(ENOMEM));
		lua_error(L);
	}
	knot_pkt_put_question(pkt, dname, rrclass, rrtype);
	knot_wire_set_rd(pkt->wire);

	/* Add OPT RR */
	pkt->opt_rr = knot_rrset_copy(worker->engine->resolver.opt_rr, NULL);
	if (!pkt->opt_rr) {
		knot_pkt_free(&pkt);
		return kr_error(ENOMEM);
	}
	if (options->DNSSEC_WANT) {
		knot_edns_set_do(pkt->opt_rr);
	}

	if (options->DNSSEC_CD) {
		knot_wire_set_cd(pkt->wire);
	}

	/* Create task and start with a first question */
	struct qr_task *task = worker_resolve_start(worker, pkt, *options);
	if (!task) {
		knot_rrset_free(&pkt->opt_rr, NULL);
		knot_pkt_free(&pkt);
		lua_pushstring(L, "couldn't create a resolution request");
		lua_error(L);
	}

	/* Add initialisation callback */
	if (lua_isfunction(L, 5)) {
		lua_pushvalue(L, 5);
		lua_pushlightuserdata(L, worker_task_request(task));
		(void) execute_callback(L, 1);
	}

	/* Start execution */
	int ret = worker_resolve_exec(task, pkt);
	lua_pushboolean(L, ret == 0);
	knot_rrset_free(&pkt->opt_rr, NULL);
	knot_pkt_free(&pkt);
	return 1;
}

static inline double getseconds(uv_timeval_t *tv)
{
	return (double)tv->tv_sec + 0.000001*((double)tv->tv_usec);
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
	/* Add subset of rusage that represents counters. */
	uv_rusage_t rusage;
	if (uv_getrusage(&rusage) == 0) {
		lua_pushnumber(L, getseconds(&rusage.ru_utime));
		lua_setfield(L, -2, "usertime");
		lua_pushnumber(L, getseconds(&rusage.ru_stime));
		lua_setfield(L, -2, "systime");
		lua_pushnumber(L, rusage.ru_majflt);
		lua_setfield(L, -2, "pagefaults");
		lua_pushnumber(L, rusage.ru_nswap);
		lua_setfield(L, -2, "swaps");
		lua_pushnumber(L, rusage.ru_nvcsw + rusage.ru_nivcsw);
		lua_setfield(L, -2, "csw");
	}
	/* Get RSS */
	size_t rss = 0;
	if (uv_resident_set_memory(&rss) == 0) {
		lua_pushnumber(L, rss);
		lua_setfield(L, -2, "rss");
	}
	return 1;
}

int lib_worker(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "resolve_unwrapped",  wrk_resolve },
		{ "stats",    wrk_stats },
		{ NULL, NULL }
	};
	register_lib(L, "worker", lib);
	return 1;
}
