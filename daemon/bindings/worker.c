/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bindings/impl.h"

#include "daemon/worker.h"

static inline double getseconds(uv_timeval_t *tv)
{
	return (double)tv->tv_sec + 0.000001*((double)tv->tv_usec);
}

/** Return worker statistics. */
static int wrk_stats(lua_State *L)
{
	struct worker_ctx *worker = the_worker;
	if (!worker) {
		return 0;
	}
	lua_newtable(L);
	lua_pushnumber(L, worker->stats.queries);
	lua_setfield(L, -2, "queries");
	lua_pushnumber(L, worker->stats.concurrent);
	lua_setfield(L, -2, "concurrent");
	lua_pushnumber(L, worker->stats.dropped);
	lua_setfield(L, -2, "dropped");

	lua_pushnumber(L, worker->stats.timeout);
	lua_setfield(L, -2, "timeout");
	lua_pushnumber(L, worker->stats.udp);
	lua_setfield(L, -2, "udp");
	lua_pushnumber(L, worker->stats.tcp);
	lua_setfield(L, -2, "tcp");
	lua_pushnumber(L, worker->stats.tls);
	lua_setfield(L, -2, "tls");
	lua_pushnumber(L, worker->stats.ipv4);
	lua_setfield(L, -2, "ipv4");
	lua_pushnumber(L, worker->stats.ipv6);
	lua_setfield(L, -2, "ipv6");

	/* Add subset of rusage that represents counters. */
	uv_rusage_t rusage;
	if (uv_getrusage(&rusage) == 0) {
		lua_pushnumber(L, getseconds(&rusage.ru_utime));
		lua_setfield(L, -2, "usertime");
		lua_pushnumber(L, getseconds(&rusage.ru_stime));
		lua_setfield(L, -2, "systime");
		lua_pushnumber(L, rusage.ru_majflt);
		lua_setfield(L, -2, "pagefaults");
		lua_pushnumber(L, rusage.ru_nswap);
		lua_setfield(L, -2, "swaps");
		lua_pushnumber(L, rusage.ru_nvcsw + rusage.ru_nivcsw);
		lua_setfield(L, -2, "csw");
	}
	/* Get RSS */
	size_t rss = 0;
	if (uv_resident_set_memory(&rss) == 0) {
		lua_pushnumber(L, rss);
		lua_setfield(L, -2, "rss");
	}
	return 1;
}

int kr_bindings_worker(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "stats",    wrk_stats },
		{ NULL, NULL }
	};
	luaL_register(L, "worker", lib);
	return 1;
}

