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

/** @file
 * Module API definition and functions for (un)loading modules.
 */

#pragma once

#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/layer.h"

struct kr_module;
struct kr_prop;


/**
 * Export module API version (place this at the end of your module).
 *
 * @param module module name (f.e. hints)
 */
#define KR_MODULE_EXPORT(module) \
    KR_EXPORT uint32_t module ## _api() { return KR_MODULE_API; }
#define KR_MODULE_API ((uint32_t) 0x20190314)

typedef uint32_t (module_api_cb)(void);


/**
 * Module representation.
 *
 * The five symbols (init, ...) may be defined by the module as name_init(), etc;
 * all are optional and missing symbols are represented as NULLs;
 */
struct kr_module {
	char *name;

	/** Constructor.  Called after loading the module.  @return error code.
	 * Lua API: not populated, called via lua directly. */
	int (*init)(struct kr_module *self);

	/** Destructor.  Called before unloading the module.  @return error code. */
	int (*deinit)(struct kr_module *self);

	/** Configure with encoded JSON (NULL if missing).  @return error code.
	 * Lua API: not used and not useful (from C). */
	int (*config)(struct kr_module *self, const char *input);

	/** Packet processing API specs.  May be NULL.  See docs on that type. */
	const kr_layer_api_t *layer;

	/** List of properties.  May be NULL.  Terminated by { NULL, NULL, NULL }.
	 * Lua API: not used and not useful (from C). */
	const struct kr_prop *props;

	void *lib;  /**< Shared library handle or RTLD_DEFAULT; NULL for lua modules. */
	void *data; /**< Custom data context. */
};

/**
 * Module property callback.  Input and output is passed via a JSON encoded in a string.
 *
 * @param env pointer to the lua engine, i.e. struct engine *env (TODO: explicit type)
 * @param input parameter (NULL if missing/nil on lua level)
 * @return a free-form JSON output (malloc-ated)
 * @note see l_trampoline() implementation for details about the input/output conversion.
 */
typedef char *(kr_prop_cb)(void *env, struct kr_module *self, const char *input);

/**
 * Module property (named callable).
 */
struct kr_prop {
	kr_prop_cb *cb;
	const char *name;
	const char *info;
};


/**
 * Load a C module instance into memory.
 *
 * @param module module structure
 * @param name module name
 * @param path module search path
 * @return 0 or an error
 */
KR_EXPORT
int kr_module_load(struct kr_module *module, const char *name, const char *path);

/**
 * Unload module instance.
 *
 * @param module module structure
 * @note currently used even for lua modules
 */
KR_EXPORT
void kr_module_unload(struct kr_module *module);

typedef int (*kr_module_init_cb)(struct kr_module *);
/**
 * Get embedded module's init function by name (or NULL).
 */
KR_EXPORT
kr_module_init_cb kr_module_get_embedded(const char *name);

