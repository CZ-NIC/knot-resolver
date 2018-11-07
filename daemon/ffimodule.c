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

#include <uv.h>

#include "daemon/engine.h"
#include "daemon/ffimodule.h"
#include "daemon/bindings.h"
#include "lib/module.h"
#include "lib/layer.h"

#if LUA_VERSION_NUM >= 502
#define l_resume(L, argc) lua_resume((L), NULL, (argc))
#else
#define l_resume(L, argc) lua_resume((L), (argc))
#endif

/** @internal Slots for layer callbacks.
  * Each slot ID corresponds to Lua reference in module API. */
enum {
	SLOT_begin = 0,
	SLOT_reset,
	SLOT_finish,
	SLOT_consume,
	SLOT_produce,
	SLOT_checkout,
	SLOT_finalize,
	SLOT_count
};
#define SLOT_size sizeof(int)

/** @internal Helper for retrieving the right function entrypoint. */
static inline lua_State *l_ffi_preface(struct kr_module *module, const char *call) {
	lua_State *L = module->lib;
	lua_getglobal(L, module->name);
	lua_getfield(L, -1, call);
	lua_remove(L, -2);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return NULL;
	}
	lua_pushlightuserdata(L, module);
	return L;
}

/** @internal Continue with coroutine. */
static void l_ffi_resume_cb(uv_idle_t *check)
{
	lua_State *L = check->data;
	int status = l_resume(L, 0);
	if (status != LUA_YIELD) {
		uv_idle_stop(check); /* Stop coroutine */
		uv_close((uv_handle_t *)check, (uv_close_cb)free);
	}
	lua_pop(L, lua_gettop(L));
}

/** @internal Schedule deferred continuation. */
static int l_ffi_defer(lua_State *L)
{
	uv_idle_t *check = malloc(sizeof(*check));
	if (!check) {
		return kr_error(ENOMEM);
	}
	uv_idle_init(uv_default_loop(), check);
	check->data = L;
	return uv_idle_start(check, l_ffi_resume_cb);
}

/** @internal Helper for calling the entrypoint. */
static inline int l_ffi_call(lua_State *L, int argc)
{
	int status = lua_pcall(L, argc, 1, 0);
	if (status != 0) {
		fprintf(stderr, "error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return kr_error(EIO);
	}
	if (lua_isnumber(L, -1)) { /* Return code */
		status = lua_tonumber(L, -1);
	} else if (lua_isthread(L, -1)) { /* Continuations */
		status = l_ffi_defer(lua_tothread(L, -1));
	}
	lua_pop(L, 1);
	return status;
}

static int l_ffi_init(struct kr_module *module)
{
	lua_State *L = l_ffi_preface(module, "init");
	if (!L) {
		return 0;
	}
	return l_ffi_call(L, 1);
}

/** @internal Unregister layer callback reference from registry. */
#define LAYER_UNREGISTER(L, api, name) do { \
	int *cb_slot = (int *)((char *)api + sizeof(kr_layer_api_t)); \
	if (cb_slot[SLOT_ ## name] > 0) \
		luaL_unref(L, LUA_REGISTRYINDEX, cb_slot[SLOT_ ## name]); \
} while(0)

static int l_ffi_deinit(struct kr_module *module)
{
	/* Deinit the module in Lua (if possible) */
	int ret = 0;
	lua_State *L = module->lib;
	if (l_ffi_preface(module, "deinit")) {
		ret = l_ffi_call(L, 1);
	}
	/* Free the layer API wrapper (unconst it) */
	kr_layer_api_t* api = module->data;
	if (api) {
		LAYER_UNREGISTER(L, api, begin);
		LAYER_UNREGISTER(L, api, finish);
		LAYER_UNREGISTER(L, api, consume);
		LAYER_UNREGISTER(L, api, produce);
		LAYER_UNREGISTER(L, api, checkout);
		LAYER_UNREGISTER(L, api, finalize);
		LAYER_UNREGISTER(L, api, reset);
		free(api);
	}
	module->lib = NULL;
	return ret;
}
#undef LAYER_UNREGISTER

/** @internal Helper for retrieving layer Lua function by name. */
#define LAYER_FFI_CALL(ctx, slot) \
	int *cb_slot = (int *)((char *)(ctx)->api + sizeof(kr_layer_api_t)); \
	if (cb_slot[SLOT_ ## slot] <= 0) { \
		return ctx->state; \
	} \
	struct kr_module *module = (ctx)->api->data; \
	lua_State *L = module->lib; \
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb_slot[SLOT_ ## slot]); \
	lua_pushnumber(L, ctx->state)

static int l_ffi_layer_begin(kr_layer_t *ctx)
{
	LAYER_FFI_CALL(ctx, begin);
	lua_pushlightuserdata(L, ctx->req);
	return l_ffi_call(L, 2);
}

static int l_ffi_layer_reset(kr_layer_t *ctx)
{
	LAYER_FFI_CALL(ctx, reset);
	lua_pushlightuserdata(L, ctx->req);
	return l_ffi_call(L, 2);
}

static int l_ffi_layer_finish(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	LAYER_FFI_CALL(ctx, finish);
	lua_pushlightuserdata(L, req);
	lua_pushlightuserdata(L, req->answer);
	return l_ffi_call(L, 3);
}

static int l_ffi_layer_consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (ctx->state & KR_STATE_FAIL) {
		return ctx->state; /* Already failed, skip */
	}
	LAYER_FFI_CALL(ctx, consume);
	lua_pushlightuserdata(L, ctx->req);
	lua_pushlightuserdata(L, pkt);
	return l_ffi_call(L, 3);
}

static int l_ffi_layer_produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (ctx->state & (KR_STATE_FAIL)) {
		return ctx->state; /* Already failed or done, skip */
	}
	LAYER_FFI_CALL(ctx, produce);
	lua_pushlightuserdata(L, ctx->req);
	lua_pushlightuserdata(L, pkt);
	return l_ffi_call(L, 3);
}

static int l_ffi_layer_checkout(kr_layer_t *ctx, knot_pkt_t *pkt, struct sockaddr *dst, int type)
{
	if (ctx->state & (KR_STATE_FAIL)) {
		return ctx->state; /* Already failed or done, skip */
	}
	LAYER_FFI_CALL(ctx, checkout);
	lua_pushlightuserdata(L, ctx->req);
	lua_pushlightuserdata(L, pkt);
	lua_pushlightuserdata(L, dst);
	lua_pushboolean(L, type == SOCK_STREAM);
	return l_ffi_call(L, 5);
}

static int l_ffi_layer_finalize(kr_layer_t *ctx)
{
	LAYER_FFI_CALL(ctx, reset);
	lua_pushlightuserdata(L, ctx->req);
	return l_ffi_call(L, 2);
}
#undef LAYER_FFI_CALL

/** @internal Conditionally register layer trampoline
  * @warning Expects 'module.layer' to be on top of Lua stack. */
#define LAYER_REGISTER(L, api, name) do { \
	int *cb_slot = (int *)((char *)api + sizeof(kr_layer_api_t)); \
	lua_getfield((L), -1, #name); \
	if (!lua_isnil((L), -1)) { \
		(api)->name = l_ffi_layer_ ## name; \
		cb_slot[SLOT_ ## name] = luaL_ref((L), LUA_REGISTRYINDEX); \
	} else { \
		lua_pop((L), 1); \
	} \
} while(0)

/** @internal Create C layer api wrapper. */
static kr_layer_api_t *l_ffi_layer_create(lua_State *L, struct kr_module *module)
{
	/* Fabricate layer API wrapping the Lua functions
	 * reserve slots after it for references to Lua callbacks. */
	const size_t api_length = sizeof(kr_layer_api_t) + (SLOT_count * SLOT_size);
	kr_layer_api_t *api = malloc(api_length);
	if (api) {
		memset(api, 0, api_length);
		LAYER_REGISTER(L, api, begin);
		LAYER_REGISTER(L, api, finish);
		LAYER_REGISTER(L, api, consume);
		LAYER_REGISTER(L, api, produce);
		LAYER_REGISTER(L, api, checkout);
		LAYER_REGISTER(L, api, finalize);
		LAYER_REGISTER(L, api, reset);
		/* Begin is always set, as it initializes layer baton. */
		api->begin = l_ffi_layer_begin;
		api->data = module;
	}
	return api;
}

/** @internal Retrieve C layer api wrapper. */
static const kr_layer_api_t *l_ffi_layer(struct kr_module *module)
{
	if (module) {
		return (const kr_layer_api_t *)module->data;
	}
	return NULL;
}
#undef LAYER_REGISTER

int ffimodule_register_lua(struct engine *engine, struct kr_module *module, const char *name)
{
	/* Register module in Lua */
	lua_State *L = engine->L;
	lua_getglobal(L, "require");
	lua_pushstring(L, name);
	if (lua_pcall(L, 1, LUA_MULTRET, 0) != 0) {
		fprintf(stderr, "error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return kr_error(ENOENT);
	}
	lua_setglobal(L, name);
	lua_getglobal(L, name);

	/* Create FFI module with trampolined functions. */
	memset(module, 0, sizeof(*module));
	module->name = strdup(name);
	module->init = &l_ffi_init;
	module->deinit = &l_ffi_deinit;
	/* Bake layer API if defined in module */
	lua_getfield(L, -1, "layer");
	if (!lua_isnil(L, -1)) {
		module->layer = &l_ffi_layer;
		module->data = l_ffi_layer_create(L, module);
	}
	module->lib = L;
	lua_pop(L, 2); /* Clear the layer + module global */
	if (module->init) {
		return module->init(module);
	}
	return kr_ok();
}
