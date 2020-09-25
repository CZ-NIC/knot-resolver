/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

/*
 * @internal These are forward decls to allow building modules with engine but without Lua.
 */
struct lua_State;

#include "lib/utils.h"
#include "lib/resolve.h"
#include "daemon/network.h"

/* @internal Array of file descriptors shorthand. */
typedef array_t(int) fd_array_t;

struct engine {
    struct kr_context resolver;
    struct network net;
    module_array_t modules;
    array_t(const struct kr_cdb_api *) backends;
    fd_array_t ipc_set;
    knot_mm_t *pool;
    char *hostname;
    struct lua_State *L;
};

int engine_init(struct engine *engine, knot_mm_t *pool);
void engine_deinit(struct engine *engine);

/** Perform a lua command within the sandbox.
 *
 *  @return zero on success.
 *  The result will be returned on the lua stack - an error message in case of failure.
 *  http://www.lua.org/manual/5.1/manual.html#lua_pcall */
int engine_cmd(struct lua_State *L, const char *str, bool raw);

/** Execute current chunk in the sandbox */
int engine_pcall(struct lua_State *L, int argc);

int engine_ipc(struct engine *engine, const char *expr);


int engine_load_sandbox(struct engine *engine);
int engine_loadconf(struct engine *engine, const char *config_path);

/** Start the lua engine and execute the config. */
int engine_start(struct engine *engine);
void engine_stop(struct engine *engine);
int engine_register(struct engine *engine, const char *name, const char *precedence, const char* ref);
int engine_unregister(struct engine *engine, const char *name);

/** Return engine light userdata. */
struct engine *engine_luaget(struct lua_State *L);

/** Set/get the per engine hostname */
char *engine_get_hostname(struct engine *engine);
int engine_set_hostname(struct engine *engine, const char *hostname);

/** Load root hints from a zonefile (or config-time default if NULL).
 *
 * @return error message or NULL (statically allocated)
 * @note exported to be usable from the hints module.
 */
KR_EXPORT
const char* engine_hint_root_file(struct kr_context *ctx, const char *file);

/* @internal Array of ip address shorthand. */
typedef array_t(char*) addr_array_t;

typedef array_t(const char*) config_array_t;

typedef struct {
	int fd;
	endpoint_flags_t flags; /**< .sock_type isn't meaningful here */
} flagged_fd_t;
typedef array_t(flagged_fd_t) flagged_fd_array_t;

struct args {
	addr_array_t addrs, addrs_tls, addrs_xdp;
	flagged_fd_array_t fds;
	int control_fd;
	int forks;
	config_array_t config;
	const char *rundir;
	bool interactive;
	bool quiet;
	bool tty_binary_output;
};

/** Pointer to kresd arguments. */
KR_EXPORT extern struct args *the_args;
