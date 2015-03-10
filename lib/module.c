#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

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
	auto_free char *symbol = kr_strcatdup(2, prefix, name);
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

static int bootstrap_libgo(struct kr_module *module)
{
	/* Check if linked against compatible libgo */
	void (*go_check)(void) = dlsym(module->lib, "runtime_check");
	void (*go_args)(int, void*) = dlsym(module->lib, "runtime_args");
	void (*go_init_os)(void) = dlsym(module->lib, "runtime_osinit");
	void (*go_init_sched)(void) = dlsym(module->lib, "runtime_schedinit");
	void (*go_init_main)(void) = dlsym(module->lib, "__go_init_main");
	if ((go_check && go_args && go_init_os && go_init_sched && go_init_main) == false) {
		return kr_error(EINVAL);
	}

	/*
	 * Bootstrap runtime - this is minimal runtime, we would need a running scheduler
	 * and gc for coroutines and memory allocation. That would require a custom "world loop",
	 * message passing, and either runtime sharing or module isolation.
	 * https://github.com/gcc-mirror/gcc/blob/gcc-4_9_2-release/libgo/runtime/proc.c#L457
	 */
	char *fake_argv[2] = {
		getenv("_"),
		NULL
	};
	go_check();
	go_args(1, fake_argv);
	go_init_os();
	go_init_sched();
	go_init_main();

	return kr_ok();
}


static int load_libgo(struct kr_module *module, module_api_cb **module_api)
{
	/* Bootstrap libgo */
	int ret = bootstrap_libgo(module);
	if (ret != 0) {
		return ret;
	}

	/* Enforced prefix for now. */
	const char *module_prefix = "main.";
	
	*(void **) (module_api)      = load_symbol(module->lib, module_prefix, "Api");
	*(void **) (&module->init)   = load_symbol(module->lib, module_prefix, "Init");
	*(void **) (&module->deinit) = load_symbol(module->lib, module_prefix, "Deinit");
	*(void **) (&module->config) = load_symbol(module->lib, module_prefix, "Config");
	*(void **) (&module->layer)  = load_symbol(module->lib, module_prefix, "Layer");

	return kr_ok();
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
 	auto_free char *module_prefix = kr_strcatdup(2, name, "_");	
	*(void **) (&module->init)   = load_symbol(module->lib, module_prefix, "init");
	*(void **) (&module->deinit) = load_symbol(module->lib, module_prefix, "deinit");
	*(void **) (&module->config) = load_symbol(module->lib, module_prefix, "config");
	*(void **) (&module->layer)  = load_symbol(module->lib, module_prefix, "layer");
	module_api_cb *module_api = NULL;
	*(void **) (&module_api) = load_symbol(module->lib, module_prefix, "api");

	/* No API version, try loading it as Go module. */
	if (module->lib != RTLD_DEFAULT && module_api == NULL) {
		(void) load_libgo(module, &module_api);
	}

	/* Check module API version (if declared). */
	if (module_api == NULL) {
		kr_module_unload(module);
		return kr_error(KNOT_ENOENT);
	} else if (module_api() != KR_MODULE_API) {
		kr_module_unload(module);
		return kr_error(ENOTSUP);
	}

	/* Initialize module */
	if (module->init) {
		module->init(module);
	}

	return kr_ok();
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
}
