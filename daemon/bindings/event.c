/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bindings/impl.h"

#include "daemon/worker.h"

#include <unistd.h>
#include <uv.h>

static void event_free(uv_timer_t *timer)
{
	struct worker_ctx *worker = timer->loop->data;
	lua_State *L = worker->engine->L;
	int ref = (intptr_t) timer->data;
	luaL_unref(L, LUA_REGISTRYINDEX, ref);
	free(timer);
}

static void event_callback(uv_timer_t *timer)
{
	struct worker_ctx *worker = timer->loop->data;
	lua_State *L = worker->engine->L;

	/* Retrieve callback and execute */
	lua_rawgeti(L, LUA_REGISTRYINDEX, (intptr_t) timer->data);
	lua_rawgeti(L, -1, 1);
	lua_pushinteger(L, (intptr_t) timer->data);
	int ret = execute_callback(L, 1);
	/* Free callback if not recurrent or an error */
	if (ret != 0 || (uv_timer_get_repeat(timer) == 0 && uv_is_active((uv_handle_t *)timer) == 0)) {
		if (!uv_is_closing((uv_handle_t *)timer)) {
			uv_close((uv_handle_t *)timer, (uv_close_cb) event_free);
		}
	}
}

static void event_fdcallback(uv_poll_t* handle, int status, int events)
{
	struct worker_ctx *worker = handle->loop->data;
	lua_State *L = worker->engine->L;

	/* Retrieve callback and execute */
	lua_rawgeti(L, LUA_REGISTRYINDEX, (intptr_t) handle->data);
	lua_rawgeti(L, -1, 1);
	lua_pushinteger(L, (intptr_t) handle->data);
	lua_pushinteger(L, status);
	lua_pushinteger(L, events);
	int ret = execute_callback(L, 3);
	/* Free callback if not recurrent or an error */
	if (ret != 0) {
		if (!uv_is_closing((uv_handle_t *)handle)) {
			uv_close((uv_handle_t *)handle, (uv_close_cb) event_free);
		}
	}
}

static int event_sched(lua_State *L, unsigned timeout, unsigned repeat)
{
	uv_timer_t *timer = malloc(sizeof(*timer));
	if (!timer)
		lua_error_p(L, "out of memory");

	/* Start timer with the reference */
	uv_loop_t *loop = uv_default_loop();
	uv_timer_init(loop, timer);
	int ret = uv_timer_start(timer, event_callback, timeout, repeat);
	if (ret != 0) {
		free(timer);
		lua_error_p(L, "couldn't start the event");
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushpointer(L, timer);
	lua_rawseti(L, -2, 2);
	int ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Save reference to the timer */
	timer->data = (void *) (intptr_t)ref;
	lua_pushinteger(L, ref);
	return 1;
}

static int event_after(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2))
		lua_error_p(L, "expected 'after(number timeout, function)'");

	return event_sched(L, lua_tointeger(L, 1), 0);
}

static int event_recurrent(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2))
		lua_error_p(L, "expected 'recurrent(number interval, function)'");

	return event_sched(L, 0, lua_tointeger(L, 1));
}

static int event_cancel(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 1 || !lua_isnumber(L, 1))
		lua_error_p(L, "expected 'cancel(number event)'");

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	bool ok = lua_istable(L, -1);

	/* Close the timer */
	uv_handle_t **timer_pp = NULL;
	if (ok) {
		lua_rawgeti(L, -1, 2);
		timer_pp = lua_touserdata(L, -1);
		ok = timer_pp && *timer_pp;
		/* That have been sufficient safety checks, hopefully. */
	}
	if (ok && !uv_is_closing(*timer_pp)) {
		uv_close(*timer_pp, (uv_close_cb)event_free);
	}
	lua_pushboolean(L, ok);
	return 1;
}

static int event_reschedule(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isnumber(L, 2))
		lua_error_p(L, "expected 'reschedule(number event, number timeout)'");

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	bool ok = lua_istable(L, -1);

	/* Reschedule the timer */
	uv_handle_t **timer_pp = NULL;
	if (ok) {
		lua_rawgeti(L, -1, 2);
		timer_pp = lua_touserdata(L, -1);
		ok = timer_pp && *timer_pp;
		/* That have been sufficient safety checks, hopefully. */
	}
	if (ok && !uv_is_closing(*timer_pp)) {
		int ret = uv_timer_start((uv_timer_t *)*timer_pp,
				event_callback, lua_tointeger(L, 2), 0);
		if (ret != 0) {
			uv_close(*timer_pp, (uv_close_cb)event_free);
			ok = false;
		}
	}
	lua_pushboolean(L, ok);
	return 1;
}

static int event_fdwatch(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2))
		lua_error_p(L, "expected 'socket(number fd, function)'");

	uv_poll_t *handle = malloc(sizeof(*handle));
	if (!handle)
		lua_error_p(L, "out of memory");

	/* Start timer with the reference */
	int sock = lua_tointeger(L, 1);
	uv_loop_t *loop = uv_default_loop();
	int ret = uv_poll_init(loop, handle, sock);
	if (ret == 0)
		ret = uv_poll_start(handle, UV_READABLE, event_fdcallback);
	if (ret != 0) {
		free(handle);
		lua_error_p(L, "couldn't start event poller");
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushpointer(L, handle);
	lua_rawseti(L, -2, 2);
	int ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Save reference to the timer */
	handle->data = (void *) (intptr_t)ref;
	lua_pushinteger(L, ref);
	return 1;
}

int kr_bindings_event(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "after",      event_after },
		{ "recurrent",  event_recurrent },
		{ "cancel",     event_cancel },
		{ "socket",     event_fdwatch },
		{ "reschedule", event_reschedule },
		{ NULL, NULL }
	};

	luaL_register(L, "event", lib);
	return 1;
}

