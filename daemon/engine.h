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

#pragma once

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "lib/resolve.h"
#include "lib/generic/array.h"

struct engine {
    struct kr_context resolver;
    modulelist_t modules;
    mm_ctx_t *pool;
    lua_State *L;
};

int engine_init(struct engine *engine, mm_ctx_t *pool);
void engine_deinit(struct engine *engine);
int engine_cmd(struct engine *engine, const char *str);
int engine_start(struct engine *engine);
void engine_stop(struct engine *engine);
int engine_register(struct engine *engine, const char *module);
int engine_unregister(struct engine *engine, const char *module);
/** Return engine light userdata. */
void engine_lualib(struct engine *engine, const char *name, lua_CFunction lib_cb);
struct engine *engine_luaget(lua_State *L);