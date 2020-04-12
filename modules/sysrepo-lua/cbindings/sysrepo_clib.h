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
#include <libyang/libyang.h>

#include "common/sysrepo_conf.h"

/** Generates prototype for functions exporting string constants from C to Lua */
#define EXPORT_STRDEF_TO_LUA(name) char *get_strdef_##name(void);
/** Generates function to be used from within Lua to get access to string constants. */
#define EXPORT_STRDEF_TO_LUA_IMPL(name) \
	char *get_strdef_##name()       \
	{                               \
		return name;            \
	}

EXPORT_STRDEF_TO_LUA(YM_COMMON)
EXPORT_STRDEF_TO_LUA(XPATH_BASE)

typedef struct el_subscription_ctx el_subscription_ctx_t;
/** Callback for our sysrepo subscriptions */
typedef void (*el_subsription_cb)(el_subscription_ctx_t *el_subscr, int status);
/** Callback to Lua for applying configuration */
typedef void (*apply_conf_f)(struct lyd_node *root);
typedef struct lyd_node* (*read_conf_f)();

KR_EXPORT int sysrepo_init(apply_conf_f apply_conf_callback, read_conf_f read_conf_callback);
KR_EXPORT int sysrepo_deinit(void);

/** Given a libyang node, returns it's first child (or NULL if there aren't any) */
KR_EXPORT struct lyd_node* node_child_first(struct lyd_node* parent);
/** Given a libyang node, return next sibling or NULL if there isn't any */
KR_EXPORT struct lyd_node* node_child_next(struct lyd_node* prev_child);
/** Given a libyang node, return it's name from schema */
KR_EXPORT const char* node_get_name(struct lyd_node* node);
/** Given a libyang node, return it's value as a string */
KR_EXPORT const char* node_get_value_str(struct lyd_node* node);
/** Create a new libyang leaf node */
KR_EXPORT struct lyd_node* node_new_leaf(struct lyd_node* parent, const struct lys_module* module, const char* name, const char* value);
/** Create a new libyang container node */
KR_EXPORT struct lyd_node* node_new_container(struct lyd_node* parent, const struct lys_module* module, const char* name);
/** Returns module given a schema node */
KR_EXPORT const struct lys_module* schema_get_module(const struct lys_node* schema);
/** Given a libyang schema node, returns it's first child (or NULL if there aren't any) */
KR_EXPORT const struct lys_node* schema_child_first(const struct lys_node* parent);
/** Given a libyang schema node, return next sibling or NULL if there isn't any */
KR_EXPORT const struct lys_node* schema_child_next(const struct lys_node* prev_child);
/** Given a libyang schema node, return it's name */
KR_EXPORT const char* schema_get_name(const struct lys_node* node);
/** Get schema root */
KR_EXPORT const struct lys_node* schema_root();
/** Validate data tree */
KR_EXPORT int node_validate(struct lyd_node* node);
/** Free data nodes recursively */
KR_EXPORT void node_free(struct lyd_node* node);
