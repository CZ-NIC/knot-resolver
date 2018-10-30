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
#define KR_MODULE_API ((uint32_t) 0x20180401)

typedef uint32_t (module_api_cb)(void);


/**
 * Module representation.
 *
 * The five symbols (init, ...) may be defined by the module as name_init(), etc;
 * all are optional and missing symbols are represented as NULLs;
 */
struct kr_module {
	char *name;

	/** Constructor.  Called after loading the module.  @return error code. */
	int (*init)(struct kr_module *self);
	/** Destructor.  Called before unloading the module.  @return error code. */
	int (*deinit)(struct kr_module *self);
	/** Configure with encoded JSON (NULL if missing).  @return error code. */
	int (*config)(struct kr_module *self, const char *input);
	/** Get a pointer to packet processing API specs.  See docs on that type. */
	const kr_layer_api_t * (*layer)(struct kr_module *self);
	/** Get a pointer to list of properties, terminated by { NULL, NULL, NULL }. */
	const struct kr_prop * (*props)(void);

	void *lib;      /**< Shared library handle or RTLD_DEFAULT */
	void *data;     /**< Custom data context. */
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
 */
KR_EXPORT
void kr_module_unload(struct kr_module *module);

/**
 * Get embedded module prototype by name (or NULL).
 */
KR_EXPORT
const struct kr_module * kr_module_embedded(const char *name);

