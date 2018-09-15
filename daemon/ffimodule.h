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

#pragma once

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
