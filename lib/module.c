#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/module.h"

/** Library extension. */
#if defined(__APPLE__)
 #define LIBEXT ".dylib"
#elif _WIN32
 #define LIBEXT ".lib"
#else
 #define LIBEXT ".so"
#endif

/** Check ABI version, return error on mismatch. */
#define ABI_CHECK(m, prefix, symname, required) do { \
	if ((m)->lib != RTLD_DEFAULT) { \
		module_api_cb *_api = NULL; \
		*(void **) (&_api) = load_symbol((m)->lib, (prefix), (symname)); \
		if (_api == NULL) { \
			return kr_error(ENOENT); \
		} \
		if (_api() != (required)) { \
			return kr_error(ENOTSUP); \
		} \
	}\
} while (0)

/** Load ABI by symbol names. */
#define ABI_LOAD(m, prefix, s_init, s_deinit, s_config, s_layer, s_prop) do { \
	module_prop_cb *module_prop = NULL; \
	*(void **) (&(m)->init)   = load_symbol((m)->lib, (prefix), (s_init)); \
	*(void **) (&(m)->deinit) = load_symbol((m)->lib, (prefix), (s_deinit)); \
	*(void **) (&(m)->config) = load_symbol((m)->lib, (prefix), (s_config)); \
	*(void **) (&(m)->layer)  = load_symbol((m)->lib, (prefix), (s_layer)); \
	*(void **) (&module_prop) = load_symbol((m)->lib, (prefix), (s_prop)); \
	if (module_prop != NULL) { \
		(m)->props = module_prop(); \
	} \
} while(0)

/** Load prefixed symbol. */
static void *load_symbol(void *lib, const char *prefix, const char *name)
{
	auto_free char *symbol = kr_strcatdup(2, prefix, name);
	return dlsym(lib, symbol);
}

static int load_library(struct kr_module *module, const char *name, const char *path)
{
	/* Absolute or relative path (then only library search path is used). */
	auto_free char *lib_path = NULL;
	if (path != NULL) {
		lib_path = kr_strcatdup(4, path, "/", name, LIBEXT);
	} else {
		lib_path = kr_strcatdup(2, name, LIBEXT);
	}
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
	auto_free char *module_prefix = kr_strcatdup(2, module->name, "_");
	ABI_CHECK(module, module_prefix, "api", api_required);
	ABI_LOAD(module, module_prefix, "init", "deinit", "config", "layer", "props");
	return kr_ok();
}

/** Bootstrap Go runtime from module. */
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

/** Load Go module symbols. */
static int load_ffi_go(struct kr_module *module, uint32_t api_required)
{
	/* Bootstrap libgo */
	int ret = bootstrap_libgo(module);
	if (ret != 0) {
		return ret;
	}

	/* Enforced prefix for now. */
	const char *module_prefix = "main.";
	ABI_CHECK(module, module_prefix, "Api", api_required);
	ABI_LOAD(module, module_prefix, "Init", "Deinit", "Config", "Layer", "Props");
	return kr_ok();
}

int kr_module_load(struct kr_module *module, const char *name, const char *path)
{
	if (module == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	/* Initialize. */
	memset(module, 0, sizeof(struct kr_module));
	module->name = strdup(name);
	if (module->name == NULL) {
		return kr_error(ENOMEM);
	}

	/* Search for module library, use current namespace if not found. */
	if (load_library(module, name, path) != 0) {
		/* Expand HOME env variable, as the linker may not expand it. */
		auto_free char *local_path = kr_strcatdup(2, getenv("HOME"), "/.local" MODULEDIR);
		if (load_library(module, name, local_path) != 0) {
			if (load_library(module, name, PREFIX MODULEDIR) != 0) {
				module->lib = RTLD_DEFAULT;
			}
		}
	}

	/* Try to load module ABI. */
	int ret = load_sym_c(module, KR_MODULE_API);
	if (ret != 0 && module->lib != RTLD_DEFAULT) {
		ret = load_ffi_go(module, KR_MODULE_API);
	}

	/* Module constructor. */
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

	free(module->name);

	if (module->deinit) {
		module->deinit(module);
	}

	if (module->lib && module->lib != RTLD_DEFAULT) {
		dlclose(module->lib);
	}

	memset(module, 0, sizeof(struct kr_module));
}
