/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "daemon/bindings/kres.h"
#include "daemon/bindings.h"

/* Metatable list */
#define META_PKT "kres.meta_pkt"

/* 
 * Packet interface
 */

#define WIRE_FLAGS(X) \
	X(AA,aa) X(AD,ad) X(CD,cd) X(RD,rd) X(QR,qr) X(RA,ra) X(TC,tc)
enum {
	#define X(flag, _) WIRE_ ## flag,
	WIRE_FLAGS(X)
	#undef X
};
static lookup_table_t wire_flag_names[] = {
	#define X(flag, _) { WIRE_ ## flag, #flag },
	WIRE_FLAGS(X)
	#undef X
};

static int pkt_flag(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
		int flag_id = lua_tonumber(L, 2);
		switch(flag_id) {
		#define X(flag, code) case WIRE_ ## flag: knot_wire_set_ ## code (pkt->wire); break;
		WIRE_FLAGS(X)
		#undef X
		}
	}
	return 0;
}

static int pkt_opcode(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
		knot_wire_set_opcode(pkt->wire, lua_tonumber(L, 2));
	}
	lua_pushnumber(L, knot_wire_get_opcode(pkt->wire));
	return 1;
}

static int pkt_rcode(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
		knot_wire_set_rcode(pkt->wire, lua_tonumber(L, 2));
	}
	lua_pushnumber(L, knot_wire_get_rcode(pkt->wire));
	return 1;
}

static int pkt_qtype(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	lua_pushnumber(L, knot_pkt_qtype(pkt));
	return 1;
}

static int pkt_qclass(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	lua_pushnumber(L, knot_pkt_qclass(pkt));
	return 1;	
}

static int pkt_qname(lua_State *L)
{
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	const knot_dname_t *dname = knot_pkt_qname(pkt);
	char dname_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(dname_str, dname, sizeof(dname_str));
	lua_pushstring(L, dname_str);
	return 1;	
}

#warning TODO: record interfaces

static int pkt_meta_set(lua_State *L)
{
	static const luaL_Reg pkt_wrap[] = {
		{ "flag",      pkt_flag},
		{ "rcode",     pkt_rcode},
		{ "opcode",    pkt_opcode},
		{ "qtype",     pkt_qtype },
		{ "qclass",    pkt_qclass },
		{ "qname",     pkt_qname },
		{ NULL, NULL }
	};
	luaL_newmetatable(L, META_PKT);
	luaL_setfuncs(L, pkt_wrap, 0);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);
	return 0;
}

static int pkt_meta_get(lua_State *L)
{
	luaL_getmetatable(L, META_PKT);
	lua_setmetatable(L, -2);
	return 1;
}

/**
 * Resolution context interface.
 */

#warning TODO: context interface, rplan

#define WRAP_NUMBER(L, name, val) \
	lua_pushnumber((L), (val)); \
	lua_setfield((L), -2, (name))

#define WRAP_CONST(L, name, prefix...) \
	WRAP_NUMBER(L, #name, prefix ## name)

#define WRAP_LUT(L, prefix, table) \
	lua_newtable(L); \
	for (lookup_table_t *elm = (table); elm->name; ++elm) { \
		WRAP_NUMBER((L), elm->name, elm->id); \
	} \
	lua_setfield((L), -2, (prefix))

int lib_kres(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "packet", pkt_meta_get },
		{ NULL, NULL }
	};
	/* Create module and register functions */
	register_lib(L, "kres", lib);
	/* Register states */
	WRAP_CONST(L, NOOP,    KNOT_STATE_);
	WRAP_CONST(L, CONSUME, KNOT_STATE_);
	WRAP_CONST(L, PRODUCE, KNOT_STATE_);
	WRAP_CONST(L, DONE,    KNOT_STATE_);
	WRAP_CONST(L, FAIL,    KNOT_STATE_);
	/* Register RCODE, OPCODE */
	WRAP_LUT(L, "rcode",  knot_rcode_names);
	WRAP_LUT(L, "opcode", knot_opcode_names);
	WRAP_LUT(L, "wire",   wire_flag_names);
	/* Register metatables */
	pkt_meta_set(L);
	return 1;	
}