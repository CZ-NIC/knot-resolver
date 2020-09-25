/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bindings/impl.h"


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
	if (n != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "expected 'load(string name)'");
	/* Parse precedence declaration */
	char *declaration = strdup(lua_tostring(L, 1));
	if (!declaration)
		return kr_error(ENOMEM);
	const char *name = strtok(declaration, " ");
	const char *precedence = strtok(NULL, " ");
	const char *ref = strtok(NULL, " ");
	/* Load engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_register(engine, name, precedence, ref);
	free(declaration);
	if (ret != 0) {
		if (ret == kr_error(EIDRM)) {
			lua_error_p(L, "referenced module not found");
		} else {
			lua_error_maybe(L, ret);
		}
	}

	lua_pushboolean(L, 1);
	return 1;
}

/** Unload module. */
static int mod_unload(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "expected 'unload(string name)'");
	/* Unload engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_unregister(engine, lua_tostring(L, 1));
	lua_error_maybe(L, ret);

	lua_pushboolean(L, 1);
	return 1;
}

int kr_bindings_modules(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",   mod_list },
		{ "load",   mod_load },
		{ "unload", mod_unload },
		{ NULL, NULL }
	};

	luaL_register(L, "modules", lib);
	return 1;
}

