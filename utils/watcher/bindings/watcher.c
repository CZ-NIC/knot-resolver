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

#include "bindings/impl.h"

#include "contrib/base64.h"
#include "watcher.h"

#include <stdlib.h>



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

static int watcher_server(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct watcher_context *watcher = &engine->watcher;
	if (!watcher) {
		return 0;
	}

	/* Only return current credentials. */
	if (lua_gettop(L) == 0) {
		lua_newtable(L);
		lua_pushstring(L, watcher.config.auto_start);
		lua_setfield(L, -2, "auto_start");
		lua_pushstring(L, watcher.config.auto_cache_gc);
		lua_setfield(L, -2, "auto_cache_gc");
		lua_pushnumber(L, watcher.config.kresd_instances);
		lua_setfield(L, -2, "kresd_instances");
		return 1;
	}

	lua_pushboolean(L, true);
	return 1;
}

int kr_bindings_watcher(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "server",       watcher_server },

		{ NULL, NULL }
	};
	luaL_register(L, "watcher", lib);
	return 1;
}

