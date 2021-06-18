/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdlib.h>
#include <dlfcn.h>
#include <contrib/cleanup.h>

#include "kresconfig.h"
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/module.h"


/* List of embedded modules.  These aren't (un)loaded. */
int iterate_init(struct kr_module *self);
int validate_init(struct kr_module *self);
int cache_init(struct kr_module *self);
kr_module_init_cb kr_module_get_embedded(const char *name)
{
	if (strcmp(name, "iterate") == 0)
		return iterate_init;
	if (strcmp(name, "validate") == 0)
		return validate_init;
	if (strcmp(name, "cache") == 0)
		return cache_init;
	return NULL;
}

/** Load prefixed symbol. */
static void *load_symbol(void *lib, const char *prefix, const char *name)
{
	auto_free char *symbol = kr_strcatdup(2, prefix, name);
	return dlsym(lib, symbol);
}

static int load_library(struct kr_module *module, const char *name, const char *path)
{
	if (kr_fails_assert(module && name && path))
		return kr_error(EINVAL);
	/* Absolute or relative path (then only library search path is used). */
	auto_free char *lib_path = kr_strcatdup(4, path, "/", name, LIBEXT);
	if (lib_path == NULL) {
		return kr_error(ENOMEM);
	}

	/* Workaround for buggy _fini/__attribute__((destructor)) and dlclose(),
	 * this keeps the library mapped until the program finishes though. */
	module->lib = dlopen(lib_path, RTLD_NOW | RTLD_NODELETE);
	if (module->lib) {
		return kr_ok();
	}

	return kr_error(ENOENT);
}

/** Load C module symbols. */
static int load_sym_c(struct kr_module *module, uint32_t api_required)
{
	module->init = kr_module_get_embedded(module->name);
	if (module->init) {
		return kr_ok();
	}
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wpedantic" /* casts after load_symbol() */
	/* Check if it's embedded first */
	/* Load dynamic library module */
	auto_free char *m_prefix = kr_strcatdup(2, module->name, "_");

	/* Check ABI version, return error on mismatch. */
	module_api_cb *api = load_symbol(module->lib, m_prefix, "api");
	if (api == NULL) {
		return kr_error(ENOENT);
	}
	if (api() != api_required) {
		return kr_error(ENOTSUP);
	}

	/* Load ABI by symbol names. */
	#define ML(symname) module->symname = \
		load_symbol(module->lib, m_prefix, #symname)
	ML(init);
	ML(deinit);
	ML(config);
	#undef ML
	if (load_symbol(module->lib, m_prefix, "layer")
	    || load_symbol(module->lib, m_prefix, "props")) {
		/* In case someone re-compiled against new kresd
		 * but haven't actually changed the symbols. */
		kr_log_error(LOG_GRP_SYSTEM, "module %s requires upgrade.  Please refer to "
			"https://knot-resolver.readthedocs.io/en/stable/upgrading.html",
			module->name);
		return kr_error(ENOTSUP);
	}

	return kr_ok();
	#pragma GCC diagnostic pop
}

int kr_module_load(struct kr_module *module, const char *name, const char *path)
{
	if (module == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	/* Initialize, keep userdata */
	void *data = module->data;
	memset(module, 0, sizeof(struct kr_module));
	module->data = data;
	module->name = strdup(name);
	if (module->name == NULL) {
		return kr_error(ENOMEM);
	}

	/* Search for module library. */
	if (!path || load_library(module, name, path) != 0) {
		module->lib = RTLD_DEFAULT;
	}

	/* Try to load module ABI. */
	int ret = load_sym_c(module, KR_MODULE_API);
	if (ret == 0 && module->init) {
		ret = module->init(module);
	}
	if (ret != 0) {
		kr_module_unload(module);
	}

	return ret;
}

void kr_module_unload(struct kr_module *module)
{
	if (module == NULL) {
		return;
	}

	if (module->deinit) {
		module->deinit(module);
	}

	if (module->lib && module->lib != RTLD_DEFAULT) {
		dlclose(module->lib);
	}

	free(module->name);
	memset(module, 0, sizeof(struct kr_module));
}
