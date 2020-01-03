/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>

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

/**
 * This header file defines an interface between sysrepo_clib and the rest
 * of the sysrepo module written in Lua. Functions and structs defined here
 * might be used through LuaJIT's FFI.
 */

#include "lib/defines.h"
#include "lib/utils.h"

#include "utils/common/sysrepo_conf.h"

/** Generates prototype for functions exporting string constants from C to Lua */
#define EXPORT_STRDEF_TO_LUA(name) char *get_strdef_##name(void);
/** Generates function to be used from within Lua to get access to string constants. */
#define EXPORT_STRDEF_TO_LUA_IMPL(name) \
	char *get_strdef_##name()       \
	{                               \
		return name;            \
	}

EXPORT_STRDEF_TO_LUA(YM_DIR)
EXPORT_STRDEF_TO_LUA(YM_COMMON)
EXPORT_STRDEF_TO_LUA(YM_KNOT)
EXPORT_STRDEF_TO_LUA(XPATH_BASE)

typedef struct el_subscription_ctx el_subscription_ctx_t;
/** Callback for our sysrepo subscriptions */
typedef void (*el_subsription_cb)(el_subscription_ctx_t *el_subscr, int status);
/** Callback to Lua for applying configuration */
typedef void (*set_leaf_conf_t)(sr_val_t *val);

KR_EXPORT int sysrepo_init(set_leaf_conf_t set_leaf_conf_cb);
KR_EXPORT int sysrepo_deinit(void);
