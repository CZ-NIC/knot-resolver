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

/** resolve_pkt(pkt, options, init_cb) */
static int wrk_resolve_pkt(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}

	knot_pkt_t *pkt = *(knot_pkt_t **)lua_topointer(L, 1);
	if (!pkt)
		lua_error_maybe(L, ENOMEM);

	/* Add query options */
	const struct kr_qflags *options = lua_topointer(L, 2);
	if (!options) /* but we rely on the lua wrapper when dereferencing non-NULL */
		lua_error_p(L, "invalid options");

	/* Create task and start with a first question */
	struct qr_task *task = worker_resolve_start(worker, pkt, *options);
	if (!task) {
		lua_error_p(L, "couldn't create a resolution request");
	}

	/* Add initialisation callback */
	if (lua_isfunction(L, 3)) {
		lua_pushvalue(L, 3);
		lua_pushlightuserdata(L, worker_task_request(task));
		(void) execute_callback(L, 1);
	}

	/* Start execution */
	int ret = worker_resolve_exec(task, pkt);
	lua_pushboolean(L, ret == 0);
	return 1;
}

/** resolve(qname, qtype, qclass, options, init_cb) */
static int wrk_resolve(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}

	uint8_t dname[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(dname, lua_tostring(L, 1), sizeof(dname)))
		lua_error_p(L, "invalid qname");

	/* Check class and type */
	uint16_t rrtype = lua_tointeger(L, 2);
	if (!lua_isnumber(L, 2))
		lua_error_p(L, "invalid RR type");

	uint16_t rrclass = lua_tointeger(L, 3);
	if (!lua_isnumber(L, 3)) { /* Default class is IN */
		rrclass = KNOT_CLASS_IN;
	}

	/* Add query options */
	const struct kr_qflags *options = lua_topointer(L, 4);
	if (!options) /* but we rely on the lua wrapper when dereferencing non-NULL */
		lua_error_p(L, "invalid options");

	/* Create query packet */
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_EDNS_MAX_UDP_PAYLOAD, NULL);
	if (!pkt)
		lua_error_maybe(L, ENOMEM);
	knot_pkt_put_question(pkt, dname, rrclass, rrtype);
	knot_wire_set_rd(pkt->wire);
	knot_wire_set_ad(pkt->wire);

	/* Add OPT RR */
	pkt->opt_rr = knot_rrset_copy(worker->engine->resolver.opt_rr, NULL);
	if (!pkt->opt_rr) {
		knot_pkt_free(pkt);
		lua_error_maybe(L, ENOMEM);
	}
	if (options->DNSSEC_WANT) {
		knot_edns_set_do(pkt->opt_rr);
	}

	if (options->DNSSEC_CD) {
		knot_wire_set_cd(pkt->wire);
	}

	lua_pushcfunction(L, wrk_resolve_pkt);
	lua_pushlightuserdata(L, &pkt);
	lua_pushvalue(L, 4);  /* options */
	lua_pushvalue(L, 5);  /* init_cb */
	lua_call(L, 3, 1);  /* leaves return value on stack */

	knot_rrset_free(pkt->opt_rr, NULL);
	knot_pkt_free(pkt);
	return 1;
}

static inline double getseconds(uv_timeval_t *tv)
{
	return (double)tv->tv_sec + 0.000001*((double)tv->tv_usec);
}

/** Return worker statistics. */
static int wrk_stats(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
	if (!worker) {
		return 0;
	}
	lua_newtable(L);
	lua_pushnumber(L, worker->stats.concurrent);
	lua_setfield(L, -2, "concurrent");
	lua_pushnumber(L, worker->stats.udp);
	lua_setfield(L, -2, "udp");
	lua_pushnumber(L, worker->stats.tcp);
	lua_setfield(L, -2, "tcp");
	lua_pushnumber(L, worker->stats.tls);
	lua_setfield(L, -2, "tls");
	lua_pushnumber(L, worker->stats.ipv6);
	lua_setfield(L, -2, "ipv6");
	lua_pushnumber(L, worker->stats.ipv4);
	lua_setfield(L, -2, "ipv4");
	lua_pushnumber(L, worker->stats.queries);
	lua_setfield(L, -2, "queries");
	lua_pushnumber(L, worker->stats.dropped);
	lua_setfield(L, -2, "dropped");
	lua_pushnumber(L, worker->stats.timeout);
	lua_setfield(L, -2, "timeout");
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
		{ "resolve_unwrapped",  wrk_resolve },
		{ "resolve_unwrapped_pkt",  wrk_resolve_pkt },
		{ "stats",    wrk_stats },
		{ NULL, NULL }
	};
	register_lib(L, "worker", lib);
	return 1;
}

