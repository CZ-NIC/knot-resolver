/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
 * @param module module name (e.g. policy)
 */
#define KR_MODULE_EXPORT(module) \
    KR_EXPORT uint32_t module ## _api() { return KR_MODULE_API; }
#define KR_MODULE_API ((uint32_t) 0x20210125)

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
	 * Lua modules: not populated, called via lua directly. */
	int (*init)(struct kr_module *self);

	/** Destructor.  Called before unloading the module.  @return error code. */
	int (*deinit)(struct kr_module *self);

	/** Configure with encoded JSON (NULL if missing).  @return error code.
	 * Lua modules: not used and not useful from C.
	 * When called from lua, input is JSON, like for kr_prop_cb. */
	int (*config)(struct kr_module *self, const char *input);

	/** Packet processing API specs.  May be NULL.  See docs on that type.
	 * Owned by the module code. */
	const kr_layer_api_t *layer;

	/** List of properties.  May be NULL.  Terminated by { NULL, NULL, NULL }.
	 * Lua modules: not used and not useful. */
	const struct kr_prop *props;

	/** dlopen() handle; RTLD_DEFAULT for embedded modules; NULL for lua modules. */
	void *lib;
	void *data; /**< Custom data context. */
};

/**
 * Module property callback.  Input and output is passed via a JSON encoded in a string.
 *
 * @param env pointer to the lua engine, i.e. struct engine *env (TODO: explicit type)
 * @param input parameter (NULL if missing/nil on lua level)
 * @return a free-form JSON output (malloc-ated)
 * @note see modules_create_table_for_c() implementation for details
 *       about the input/output conversion.
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
 * Load a C module instance into memory.  And call its init().
 *
 * @param module module structure.  Will be overwritten except for ->data on success.
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

