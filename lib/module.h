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

#include <libknot/processing/layer.h>
#include "lib/defines.h"
#include "lib/utils.h"

/*
 * Forward decls
 */
struct kr_module;
struct kr_prop;

/*
 * API definition.
 * @cond internal
 */
typedef uint32_t (module_api_cb)(void);
typedef int (module_init_cb)(struct kr_module *);
typedef int (module_deinit_cb)(struct kr_module *);
typedef int (module_config_cb)(struct kr_module *, const char *);
typedef const knot_layer_api_t* (module_layer_cb)(struct kr_module *);
typedef struct kr_prop *(module_prop_cb)(void);
typedef char *(kr_prop_cb)(void *, struct kr_module *, const char *);
#define KR_MODULE_API ((uint32_t) 0x20150402)
/* @endcond */

/**
 * Module property (named callable).
 * A module property has a free-form JSON output (and optional input).
 */
struct kr_prop {
    kr_prop_cb *cb;
    const char *name;
    const char *info;
};

/**
 * Module representation.
 */
struct kr_module {
    char *name;               /**< Name. */
    module_init_cb   *init;   /**< Constructor */
    module_deinit_cb *deinit; /**< Destructor */
    module_config_cb *config; /**< Configuration */
    module_layer_cb  *layer;  /**< Layer getter */
    struct kr_prop   *props;  /**< Properties */
    void *lib;                /**< Shared library handle or RTLD_DEFAULT */
    void *data;               /**< Custom data context. */
};

/**
 * Load module instance into memory.
 *
 * @param module module structure
 * @param name module name
 * @param path module search path
 * @return 0 or an error
 */
int kr_module_load(struct kr_module *module, const char *name, const char *path);

/**
 * Unload module instance.
 *
 * @param module module structure
 */
void kr_module_unload(struct kr_module *module);

/**
 * Export module API version (place this at the end of your module).
 *
 * @param module module name (f.e. hints)
 */
#define KR_MODULE_EXPORT(module) \
    uint32_t module ## _api() { return KR_MODULE_API; }
