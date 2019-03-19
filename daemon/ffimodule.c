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


#include "daemon/engine.h"
#include "daemon/ffimodule.h"
#include "lib/module.h"

#include "daemon/bindings/impl.h"

int ffimodule_register_lua(struct engine *engine, struct kr_module *module, const char *name)
{
	memset(module, 0, sizeof(*module));
	module->name = strdup(name);
	lua_State *L = engine->L;
	module->lib = L;
	/* The rest is written in lua.  FFI is inaccessible from C directly. */
	lua_getglobal(L, "modules_load_lua");
	lua_pushpointer(L, module);
	if (lua_pcall(L, 1, 0, 0) != 0) {
		kr_log_error("error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		free(module->name);
		/* It might be another error, but typically it's a module not found.
		 * Another common case could be whatever the module's init() throws. */
		return kr_error(ENOENT);
	}
	return kr_ok();
}

