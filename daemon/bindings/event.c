/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
	if (!timer) {
		format_error(L, "out of memory");
		lua_error(L);
	}

	/* Start timer with the reference */
	uv_loop_t *loop = uv_default_loop();
	uv_timer_init(loop, timer);
	int ret = uv_timer_start(timer, event_callback, timeout, repeat);
	if (ret != 0) {
		free(timer);
		format_error(L, "couldn't start the event");
		lua_error(L);
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushlightuserdata(L, timer);
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
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'after(number timeout, function)'");
		lua_error(L);
	}

	return event_sched(L, lua_tonumber(L, 1), 0);
}

static int event_recurrent(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'recurrent(number interval, function)'");
		lua_error(L);
	}
	return event_sched(L, 0, lua_tonumber(L, 1));
}

static int event_cancel(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 1 || !lua_isnumber(L, 1)) {
		format_error(L, "expected 'cancel(number event)'");
		lua_error(L);
	}

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, false);
		return 1;
	}

	/* Close the timer */
	lua_rawgeti(L, -1, 2);
	uv_handle_t *timer = lua_touserdata(L, -1);
	if (!uv_is_closing(timer)) {
		uv_close(timer, (uv_close_cb) event_free);
	}
	lua_pushboolean(L, true);
	return 1;
}

static int event_reschedule(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isnumber(L, 2)) {
		format_error(L, "expected 'reschedule(number event, number timeout)'");
		lua_error(L);
	}

	/* Fetch event if it exists */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_tointeger(L, 1));
	if (!lua_istable(L, -1)) {
		lua_pushboolean(L, false);
		return 1;
	}

	/* Reschedule the timer */
	lua_rawgeti(L, -1, 2);
	uv_handle_t *timer = lua_touserdata(L, -1);
	if (!uv_is_closing(timer)) {
		if (uv_is_active(timer)) {
			uv_timer_stop((uv_timer_t *)timer);
		}
		int ret = uv_timer_start((uv_timer_t *)timer, event_callback, lua_tointeger(L, 2), 0);
		if (ret != 0) {
			event_cancel(L);
			lua_pushboolean(L, false);
			return 1;
		}
	}
	lua_pushboolean(L, true);
	return 1;
}

static int event_fdwatch(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2 || !lua_isnumber(L, 1) || !lua_isfunction(L, 2)) {
		format_error(L, "expected 'socket(number fd, function)'");
		lua_error(L);
	}

	uv_poll_t *handle = malloc(sizeof(*handle));
	if (!handle) {
		format_error(L, "out of memory");
		lua_error(L);
	}

	/* Start timer with the reference */
	int sock = lua_tonumber(L, 1);
	uv_loop_t *loop = uv_default_loop();
#if defined(__APPLE__) || defined(__FreeBSD__)
	/* libuv is buggy and fails to create poller for
	 * kqueue sockets as it can't be fcntl'd to non-blocking mode,
	 * so we pass it a copy of standard input and then
	 * switch it with real socket before starting the poller
	 */
	int decoy_fd = dup(STDIN_FILENO);
	int ret = uv_poll_init(loop, handle, decoy_fd);
	if (ret == 0) {
		handle->io_watcher.fd = sock;
	}
	close(decoy_fd);
#else
	int ret = uv_poll_init(loop, handle, sock);
#endif
	if (ret == 0) {
		ret = uv_poll_start(handle, UV_READABLE, event_fdcallback);
	}
	if (ret != 0) {
		free(handle);
		format_error(L, "couldn't start event poller");
		lua_error(L);
	}

	/* Save callback and timer in registry */
	lua_newtable(L);
	lua_pushvalue(L, 2);
	lua_rawseti(L, -2, 1);
	lua_pushlightuserdata(L, handle);
	lua_rawseti(L, -2, 2);
	int ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Save reference to the timer */
	handle->data = (void *) (intptr_t)ref;
	lua_pushinteger(L, ref);
	return 1;
}

int lib_event(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "after",      event_after },
		{ "recurrent",  event_recurrent },
		{ "cancel",     event_cancel },
		{ "socket",     event_fdwatch },
		{ "reschedule", event_reschedule },
		{ NULL, NULL }
	};

	register_lib(L, "event", lib);
	return 1;
}

