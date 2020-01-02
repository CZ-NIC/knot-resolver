#include "conversion.h"

#include <assert.h>
#include <err.h>
#include <lauxlib.h>
#include <lua.h>
#include <luaconf.h>
#include <lualib.h>
#include <stdbool.h>
#include <sysrepo.h>

#include "daemon/engine.h"
#include "daemon/worker.h"
#include "utils/common/sysrepo_conf.h"

// FIXME proper error reporting
//     kr_log_error etc
// FIXME lua module loading

static bool _sysrepo_ffi_loaded = false;
/**
 * Loads sysrepo types into LuaJIT. Can be called multiple times, but runs only once.
 **/
static void _load_sysrepo_definitions_once(lua_State *L)
{
	// Fast check using global variables from this module.
	// Will not block the repeated initialization after module unload/load
	if (_sysrepo_ffi_loaded)
		return;
	else
		_sysrepo_ffi_loaded = true;

	// secondary check is present in the lua module itself
	// that will be slower, but should work across module reloads becase the global variable
	// is stored in global Lua context
	if (luaL_loadfile(L, LIBDIR "/kres_modules/sysrepo_ffi.lua") ||
	    lua_pcall(L, 0, LUA_MULTRET, 0))
		errx(1, "could not load sysrepo FFI loader module - '%s'\n",
		     lua_tostring(L, -1));
}

/**
 * This function is just a facade for calling Lua code. The actual
 * implementation of configuration handling is in file `conversion.lua` in
 * function with the same name.
 **/
sr_error_t set_leaf_conf(sr_val_t *value)
{
	lua_State *L = the_worker->engine->L;

	/* Make sure LuaJIT's FFI is prepared properly. */
	_load_sysrepo_definitions_once(L);

	/* conversion = require("conversion")
     * Push the conversion module onto the stack. */
	if (luaL_loadfile(L,
			  LIBDIR "/kres_modules/sysrepo_conf_applicator.lua") ||
	    lua_pcall(L, 0, LUA_MULTRET, 0))
		errx(1,
		     "could not load configuration conversion module - '%s'\n",
		     lua_tostring(L, -1));

	/* Pull function set_leaf_conf out of the counter module on top of the stack.
     */
	lua_getfield(L, -1, "set_leaf_conf");

	/* Verify that set_leaf_conf is a function. */
	if (!lua_isfunction(L, -1))
		errx(1,
		     "set_leaf_conf is not a function in lua module 'conversion'");

	/* Move the set_leaf_conf function on top of the stack one value down.
       The stack looks like this now:   [...] set_leaf_conf conversion_module */
	lua_insert(L, -2);

	/* Put our actual argument onto the stack. */
	lua_pushlightuserdata(L, value);

	/* Call set_leaf_conf(M, value). 2 arguments. 1 return value. */
	if (lua_pcall(L, 2, LUA_MULTRET, 0) != 0) {
		// calling the function failed, stack contains error message
		printf("Runtime error while calling `set_leaf_conf` - %s\n",
		       lua_tostring(L, -1));
		// pop the message, so that the stack is clean
		lua_pop(L, 1);
		// exit
		return SR_ERR_OPERATION_FAILED;
	}

	/* Right now we will either have nil or an error string
     * on the stack
     */
	if (lua_type(L, -1) == LUA_TSTRING) {
		printf("conversion function reported error - %s\n",
		       lua_tostring(L, -1));
		lua_pop(L, 1);
		return SR_ERR_INVAL_ARG;
	}

	assert(lua_type(L, -1) == LUA_TNIL);

	/* Remove the empty nil from the stack */
	lua_pop(L, 1);

	return SR_ERR_OK;
}
