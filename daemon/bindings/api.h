/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <lua.h>

/** Make all the bindings accessible from the lua state,
 * .i.e. define those lua tables. */
void kr_bindings_register(lua_State *L);

