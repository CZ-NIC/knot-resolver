/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <lua.h>

/** Make all the bindings accessible from the lua state,
 * .i.e. define those lua tables. */
void kr_bindings_register(lua_State *L);

