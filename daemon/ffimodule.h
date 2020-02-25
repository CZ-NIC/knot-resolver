/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/defines.h"
#include "lib/layer.h"
#include <lua.h>
struct engine;
struct kr_module;

/**
 * Register Lua module as a FFI module.
 * This fabricates a standard module interface,
 * that trampolines to the Lua module methods.
 *
 * @note Lua module is loaded in it's own coroutine,
 *       so it's possible to yield and resume at arbitrary
 *       places except deinit()
 *
 * @param  engine daemon engine
 * @param  module prepared module
 * @param  name   module name
 * @return        0 or an error
 */
int ffimodule_register_lua(struct engine *engine, struct kr_module *module, const char *name);

int ffimodule_init(lua_State *L);
void ffimodule_deinit(lua_State *L);

/** Static storage for faster passing of layer function parameters to lua callbacks.
 *
 * We don't need to declare it in a header, but let's give it visibility. */
KR_EXPORT extern kr_layer_t kr_layer_t_static;

