/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <uv.h>
#include <lua.h>
#include <lauxlib.h>

#include "daemon/bindings/impl.h"
#include "daemon/engine.h"
#include "daemon/ffimodule.h"
#include "daemon/worker.h"
#include "lib/module.h"
#include "lib/layer.h"

/** @internal Slots for layer callbacks.
  * Each slot ID corresponds to Lua reference in module API. */
enum {
	SLOT_begin = 0,
	SLOT_reset,
	SLOT_finish,
	SLOT_consume,
	SLOT_produce,
	SLOT_checkout,
	SLOT_answer_finalize,
	SLOT_count /* dummy, must be the last */
};

/** Lua registry indices for functions that wrap layer callbacks (shared by all lua modules). */
static int l_ffi_wrap_slots[SLOT_count] = { 0 };

/** @internal Continue with coroutine. */
static void l_ffi_resume_cb(uv_idle_t *check)
{
	lua_State *L = check->data;
	int status = lua_resume(L, 0);
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

/** Common part of calling modname.(de)init in lua.
 * The function to call should be on top of the stack and it gets popped. */
static int l_ffi_modcb(lua_State *L, struct kr_module *module)
{
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* .(de)init == nil, maybe even the module table doesn't exist */
		return kr_ok();
	}
	lua_getglobal(L, "modules_ffi_wrap_modcb");
	lua_insert(L, -2); /* swap with .(de)init */
	lua_pushpointer(L, module);
	if (lua_pcall(L, 2, 0, 0) == 0)
		return kr_ok();
	kr_log_error(LOG_GRP_SYSTEM, "[system] error: %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);
	return kr_error(1);
}

static int l_ffi_deinit(struct kr_module *module)
{
	/* Call .deinit(), if it exists. */
	lua_State *L = the_worker->engine->L;
	lua_getglobal(L, module->name);
	lua_getfield(L, -1, "deinit");
	const int ret = l_ffi_modcb(L, module);
	lua_pop(L, 1); /* the module's table */

	const kr_layer_api_t *api = module->layer;
	if (!api) {
		return ret;
	}
	/* Unregister layer callback references from registry. */
	for (int si = 0; si < SLOT_count; ++si) {
		if (api->cb_slots[si] > 0) {
			luaL_unref(L, LUA_REGISTRYINDEX, api->cb_slots[si]);
		}
	}
	free_const(api);
	return ret;
}

kr_layer_t kr_layer_t_static;

/** @internal Helper for calling a layer Lua function by e.g. SLOT_begin. */
static int l_ffi_call_layer(kr_layer_t *ctx, int slot_ix)
{
	const int wrap_slot = l_ffi_wrap_slots[slot_ix];
	const int cb_slot = ctx->api->cb_slots[slot_ix];
	kr_require(wrap_slot > 0 && cb_slot > 0);
	lua_State *L = the_worker->engine->L;
	lua_rawgeti(L, LUA_REGISTRYINDEX, wrap_slot);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb_slot);
	/* We pass the content of *ctx via a global structure to avoid
	 * lua (full) userdata, as that's relatively expensive (GC-allocated).
	 * Performance: copying isn't ideal, but it's not visible in profiles. */
	memcpy(&kr_layer_t_static, ctx, sizeof(*ctx));

	int ret = lua_pcall(L, 1, 1, 0);
	/* Handle result of the pcall.
	 * Default state: ctx->req->state seems safer than ctx->state,
	 * in case the pcall touched req->state. */
	int state = ctx->req->state;
	if (ret) { /* Exception or another lua problem. */
		state = KR_STATE_FAIL;
		kr_log_error(LOG_GRP_SYSTEM, "[system] error: %s\n", lua_tostring(L, -1));

	} else if (lua_isnumber(L, -1)) { /* Explicitly returned state. */
		state = lua_tointeger(L, -1);
		if (!kr_state_consistent(state)) {
			kr_log_error(LOG_GRP_SYSTEM, "[system] error: nonsense state returned from lua module layer: %d\n",
					state);
			state = KR_STATE_FAIL;
		}

	} else if (lua_isnil(L, -1)) { /* Don't change state. */

	} else if (kr_fails_assert(!lua_isthread(L, -1))) { /* Continuations */
		/* TODO: unused, possibly in a bad shape.  Meant KR_STATE_YIELD? */
		if (l_ffi_defer(lua_tothread(L, -1)) != 0)
			state = KR_STATE_FAIL;

	} else { /* Nonsense returned. */
		state = KR_STATE_FAIL;
		kr_log_error(LOG_GRP_SYSTEM, "[system] error: nonsense returned from lua module layer: %s\n",
				lua_tostring(L, -1));
		/* Unfortunately we can't easily get name of the module/function here. */
	}
	lua_pop(L, 1);
	return state;
}

static int l_ffi_layer_begin(kr_layer_t *ctx)
{
	return l_ffi_call_layer(ctx, SLOT_begin);
}

static int l_ffi_layer_reset(kr_layer_t *ctx)
{
	return l_ffi_call_layer(ctx, SLOT_reset);
}

static int l_ffi_layer_finish(kr_layer_t *ctx)
{
	ctx->pkt = ctx->req->answer;
	return l_ffi_call_layer(ctx, SLOT_finish);
}

static int l_ffi_layer_consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (ctx->state & KR_STATE_FAIL) {
		return ctx->state; /* Already failed, skip */
	}
	ctx->pkt = pkt;
	return l_ffi_call_layer(ctx, SLOT_consume);
}

static int l_ffi_layer_produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (ctx->state & KR_STATE_FAIL) {
		return ctx->state; /* Already failed, skip */
	}
	ctx->pkt = pkt;
	return l_ffi_call_layer(ctx, SLOT_produce);
}

static int l_ffi_layer_checkout(kr_layer_t *ctx, knot_pkt_t *pkt,
				struct sockaddr *dst, int type)
{
	if (ctx->state & KR_STATE_FAIL) {
		return ctx->state; /* Already failed, skip */
	}
	ctx->pkt = pkt;
	ctx->dst = dst;
	ctx->is_stream = (type == SOCK_STREAM);
	return l_ffi_call_layer(ctx, SLOT_checkout);
}

static int l_ffi_layer_answer_finalize(kr_layer_t *ctx)
{
	return l_ffi_call_layer(ctx, SLOT_answer_finalize);
}

int ffimodule_init(lua_State *L)
{
	/* Wrappers defined in ./lua/sandbox.lua */
	/* for API: (int state, kr_request_t *req) */
	lua_getglobal(L, "modules_ffi_layer_wrap1");
	const int wrap1 = luaL_ref(L, LUA_REGISTRYINDEX);
	/* for API: (int state, kr_request_t *req, knot_pkt_t *) */
	lua_getglobal(L, "modules_ffi_layer_wrap2");
	const int wrap2 = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_getglobal(L, "modules_ffi_layer_wrap_checkout");
	const int wrap_checkout = luaL_ref(L, LUA_REGISTRYINDEX);
	if (wrap1 == LUA_REFNIL || wrap2 == LUA_REFNIL || wrap_checkout == LUA_REFNIL) {
		return kr_error(ENOENT);
	}

	const int slots[SLOT_count] = {
		[SLOT_begin]   = wrap1,
		[SLOT_reset]   = wrap1,
		[SLOT_finish]  = wrap2,
		[SLOT_consume] = wrap2,
		[SLOT_produce] = wrap2,
		[SLOT_checkout] = wrap_checkout,
		[SLOT_answer_finalize] = wrap1,
	};
	memcpy(l_ffi_wrap_slots, slots, sizeof(l_ffi_wrap_slots));
	return kr_ok();
}
void ffimodule_deinit(lua_State *L)
{
	/* Unref each wrapper function from lua.
	 * It's probably useless, as we're about to destroy lua_State, but... */
	const int wrapsIndices[] = {
		SLOT_begin,
		SLOT_consume,
		SLOT_checkout,
	};
	for (int i = 0; i < sizeof(wrapsIndices) / sizeof(wrapsIndices[0]); ++i) {
		luaL_unref(L, LUA_REGISTRYINDEX, l_ffi_wrap_slots[wrapsIndices[i]]);
	}
}

/** @internal Conditionally register layer trampoline
  * @warning Expects 'module.layer' to be on top of Lua stack. */
#define LAYER_REGISTER(L, api, name) do { \
	int *cb_slot = (api)->cb_slots + SLOT_ ## name; \
	lua_getfield((L), -1, #name); \
	if (!lua_isnil((L), -1)) { \
		(api)->name = l_ffi_layer_ ## name; \
		*cb_slot = luaL_ref((L), LUA_REGISTRYINDEX); \
	} else { \
		lua_pop((L), 1); \
	} \
} while(0)

/** @internal Create C layer api wrapper. */
static kr_layer_api_t *l_ffi_layer_create(lua_State *L, struct kr_module *module)
{
	/* Fabricate layer API wrapping the Lua functions
	 * reserve slots after it for references to Lua callbacks. */
	const size_t api_length = offsetof(kr_layer_api_t, cb_slots)
				+ (SLOT_count * sizeof(module->layer->cb_slots[0]));
	kr_layer_api_t *api = calloc(1, api_length);
	if (api) {
		LAYER_REGISTER(L, api, begin);
		LAYER_REGISTER(L, api, finish);
		LAYER_REGISTER(L, api, consume);
		LAYER_REGISTER(L, api, produce);
		LAYER_REGISTER(L, api, checkout);
		LAYER_REGISTER(L, api, answer_finalize);
		LAYER_REGISTER(L, api, reset);
	}
	return api;
}

#undef LAYER_REGISTER

int ffimodule_register_lua(struct engine *engine, struct kr_module *module, const char *name)
{
	/* Register module in Lua */
	lua_State *L = engine->L;
	lua_getglobal(L, "require");
	lua_pushfstring(L, "kres_modules.%s", name);
	if (lua_pcall(L, 1, LUA_MULTRET, 0) != 0) {
		kr_log_error(LOG_GRP_SYSTEM, "[system] error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return kr_error(ENOENT);
	}
	lua_setglobal(L, name);
	lua_getglobal(L, name);

	/* Create FFI module with trampolined functions. */
	memset(module, 0, sizeof(*module));
	module->name = strdup(name);
	module->deinit = &l_ffi_deinit;
	/* Bake layer API if defined in module */
	lua_getfield(L, -1, "layer");
	if (!lua_isnil(L, -1)) {
		module->layer = l_ffi_layer_create(L, module);
	}
	lua_pop(L, 1); /* .layer table */

	/* Now call .init(), if it exists. */
	lua_getfield(L, -1, "init");
	const int ret = l_ffi_modcb(L, module);
	lua_pop(L, 1); /* the module's table */
	return ret;
}
