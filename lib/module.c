#include <stdlib.h>
#include <dlfcn.h>

#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/module.h"

/*! \brief Library extension. */
static inline const char *library_ext(void)
{
#if defined(__APPLE__)
	return ".dylib";
#elif _WIN32
	return ".lib";
#else
	return ".so";
#endif	
}

static void *load_symbol(void *lib, const char *prefix, const char *name)
{
	auto_free char *symbol = kr_strcatdup(3, prefix, "_", name);
	return dlsym(lib, symbol);
}

static int load_library(struct kr_module *module, const char *name, const char *path)
{
	const char *ext = library_ext();
	auto_free char *lib_path = NULL;
	if (path != NULL) {
		lib_path = kr_strcatdup(4, path, "/", name, ext);
	} else {
		lib_path = kr_strcatdup(2, name, ext);
	}
	if (lib_path == NULL) {
		return kr_error(ENOMEM);
	}

	module->lib = dlopen(lib_path, RTLD_LAZY);
	if (module->lib) {
		return kr_ok();
	}

	return kr_error(ENOENT);
}

int kr_module_load(struct kr_module *module, const char *name, const char *path)
{
	if (module == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	/* Search for module library. */
	memset(module, 0, sizeof(struct kr_module));
	if (load_library(module, name, path) != 0) {
		/* Expand HOME env variable, as the linker may not expand it. */
		auto_free char *local_path = kr_strcatdup(2, getenv("HOME"), "/.local" MODULEDIR);
		if (load_library(module, name, local_path) != 0) {
			if (load_library(module, name, PREFIX MODULEDIR) != 0) {	
			}
		}
	}

	/* It's okay if it fails, then current exec space is searched. */
	if (module->lib == NULL) {
		module->lib = RTLD_DEFAULT;
	}

	/* Load all symbols. */
 	module_api_cb *module_api = NULL;
	*(void **) (&module_api)     = load_symbol(module->lib, name, "api");
	*(void **) (&module->init)   = load_symbol(module->lib, name, "init");
	*(void **) (&module->deinit) = load_symbol(module->lib, name, "deinit");
	*(void **) (&module->config) = load_symbol(module->lib, name, "config");
	*(void **) (&module->layer)  = load_symbol(module->lib, name, "layer");

	/* Check module API version (if declared). */
	if (module_api && module_api() > KR_MODULE_API) {
		return kr_error(ENOTSUP);
	}

	/* Initialize module */
	if (module->init) {
		return module->init(module);
	}

	return kr_ok();
}

void kr_module_unload(struct kr_module *module)
{
	if (module->deinit) {
		module->deinit(module);
	}

	if (module->lib && module->lib != RTLD_DEFAULT) {
		dlclose(module->lib);
	}
}