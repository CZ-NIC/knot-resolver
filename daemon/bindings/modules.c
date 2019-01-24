/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

int kr_bindings_modules(lua_State *L)
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

