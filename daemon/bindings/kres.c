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

#include <libknot/descriptor.h>
#include "daemon/bindings/kres.h"
#include "daemon/bindings.h"

#define WRAP_NUMBER(L, name, val) \
	lua_pushnumber((L), (val)); \
	lua_setfield((L), -2, (name))

#define WRAP_CONST(L, name, prefix...) \
	WRAP_NUMBER(L, #name, prefix ## name)

#define WRAP_LUT(L, prefix, table) \
	lua_newtable(L); \
	for (const lookup_table_t *elm = (table); elm->name; ++elm) { \
		WRAP_NUMBER((L), elm->name, elm->id); \
	} \
	lua_setfield((L), -2, (prefix))

/** @internal Register metatable. */
static void lua_register_meta(lua_State *L, const luaL_Reg *funcs, const char *name)
{
	luaL_newmetatable(L, name); \
	luaL_setfuncs(L, funcs, 0); \
	lua_pushvalue(L, -1); \
	lua_setfield(L, -2, "__index"); \
	lua_pop(L, 1);
}

/** @internal Shortcut for dname conversion. */
static inline void lua_pushdname(lua_State *L, const knot_dname_t *name)
{
	char dname_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(dname_str, name, sizeof(dname_str));
	lua_pushstring(L, dname_str);
}

/*
 * Record types, since the libknot doesn't export them.
 */
#define RECORD_TYPES(X) \
	X(A) X(NS) X(CNAME) X(SOA) X(PTR) X(HINFO) X(MINFO) X(MX) \
	X(TXT) X(RP) X(AFSDB) X(RT) X(SIG) X(KEY) X(AAAA) X(LOC) \
	X(SRV) X(NAPTR) X(KX) X(CERT) X(DNAME) X(OPT) X(APL) X(DS) \
	X(SSHFP) X(IPSECKEY) X(RRSIG) X(NSEC) X(DNSKEY) X(DHCID) \
	X(NSEC3) X(NSEC3PARAM) X(TLSA) X(CDS) X(CDNSKEY) X(SPF) \
	X(NID) X(L32) X(L64) X(LP) X(EUI48) X(EUI64) X(TKEY) \
	X(TSIG) X(IXFR) X(AXFR) X(ANY)

static lookup_table_t rrtype_names[] = {
	#define X(rc) { KNOT_RRTYPE_ ## rc, #rc },
	RECORD_TYPES(X)
	#undef X
	{ 0, NULL }
};

/* 
 * Packet interface
 * @note Packets are always light userdata, use single pointers.
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
	{ 0, NULL }
};

#define PKT_UDATA_CHECK(L) \
	if (!lua_touserdata(L, 1)) { \
		lua_pushliteral(L, "bad parameters, expected (pkt[, newvalue])"); \
		lua_error(L); \
	}

static int pkt_flag(lua_State *L)
{
	PKT_UDATA_CHECK(L);
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
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
		knot_wire_set_opcode(pkt->wire, lua_tonumber(L, 2));
	}
	lua_pushnumber(L, knot_wire_get_opcode(pkt->wire));
	return 1;
}

static int pkt_rcode(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
		knot_wire_set_rcode(pkt->wire, lua_tonumber(L, 2));
	}
	lua_pushnumber(L, knot_wire_get_rcode(pkt->wire));
	return 1;
}

static int pkt_qtype(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	lua_pushnumber(L, knot_pkt_qtype(pkt));
	return 1;
}

static int pkt_qclass(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	lua_pushnumber(L, knot_pkt_qclass(pkt));
	return 1;
}

static int pkt_qname(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	lua_pushdname(L, knot_pkt_qname(pkt));
	return 1;
}

static int pkt_question(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) < 4) {
		return 0;
	}
	uint8_t dname[KNOT_DNAME_MAXLEN];
	knot_dname_from_str(dname, lua_tostring(L, 2), sizeof(dname));
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), dname) || pkt->rrset_count > 0) {
		KR_PKT_RECYCLE(pkt);
		knot_pkt_put_question(pkt, dname, lua_tointeger(L, 3), lua_tointeger(L, 4));
		pkt->parsed = pkt->size;
	}
	return 0;
}

static int pkt_begin(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_isnil(L, 2) || lua_tonumber(L, 2) < pkt->current) {
		lua_pushliteral(L, "bad parameters, expected packet section >= current");
		lua_error(L);
	}
	knot_pkt_begin(pkt, lua_tointeger(L, 2));
	return 0;
}

static int pkt_add(lua_State *L)
{
	PKT_UDATA_CHECK(L);
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	if (lua_gettop(L) < 6) {
		return 0;
	}
	/* Get parameters */
	uint8_t dname[KNOT_DNAME_MAXLEN];
	knot_dname_from_str(dname, lua_tostring(L, 2), sizeof(dname));
	uint16_t rrclass = lua_tointeger(L, 3);
	uint16_t rrtype = lua_tointeger(L, 4);
	uint32_t ttl = lua_tointeger(L, 5);
	size_t rdlen = 0;
	const char *raw_data = lua_tolstring(L, 6, &rdlen);
	/* Create empty RR */
	knot_rrset_t rr;
	knot_rrset_init(&rr, knot_dname_copy(dname, &pkt->mm), rrtype, rrclass);
	/* Create RDATA */
	knot_rdata_t rdata[knot_rdata_array_size(rdlen)];
	knot_rdata_init(rdata, rdlen, (const uint8_t *)raw_data, ttl);
	knot_rdataset_add(&rr.rrs, rdata, &pkt->mm);
	/* Append RR */
	int ret = knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
	lua_pushboolean(L, ret == 0);
	pkt->parsed = pkt->size;
	return 1;
}

static int pkt_get(lua_State *L)
{
	if (lua_gettop(L) < 3) {
		return 0;
	}
	/* Get parameters */
	knot_pkt_t *pkt = lua_touserdata(L, 1);
	uint16_t section_id = lua_tointeger(L, 2);
	uint16_t index = lua_tointeger(L, 3);
	/* Get RR */
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || sec->count <= index) {
		return 0;
	}
	const knot_rrset_t *rr = knot_pkt_rr(sec, index);
	lua_newtable(L);
	lua_pushdname(L, rr->owner);
	lua_setfield(L, -2, "owner");
	lua_pushnumber(L, rr->rclass);
	lua_setfield(L, -2, "class");
	lua_pushnumber(L, rr->type);
	lua_setfield(L, -2, "type");
	lua_pushnumber(L, knot_rrset_ttl(rr));
	lua_setfield(L, -2, "ttl");
	lua_pushlightuserdata(L, (void *)&rr->rrs);
	lua_setfield(L, -2, "rdata");
	return 1;
}

static int pkt_meta_register(lua_State *L)
{
	static const luaL_Reg wrap[] = {
		{ "flag",      pkt_flag   },
		{ "rcode",     pkt_rcode  },
		{ "opcode",    pkt_opcode },
		{ "qtype",     pkt_qtype  },
		{ "qclass",    pkt_qclass },
		{ "qname",     pkt_qname  },
		{ "question",  pkt_question },
		{ "begin",     pkt_begin },
		{ "add",       pkt_add },
		{ "get",       pkt_get },
		{ NULL, NULL }
	};
	lua_register_meta(L, wrap, META_PKT);
	return 0;
}

/**
 * Query interface.
 * @note Query is a full userdata, use double pointers.
 */

static int query_qtype(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	lua_pushnumber(L, qry->stype);
	return 1;
}

static int query_qclass(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	lua_pushnumber(L, qry->sclass);
	return 1;	
}

static int query_qname(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	lua_pushdname(L, qry->sname);
	return 1;	
}

static int query_flag(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	if (lua_gettop(L) < 2 || !lua_isnumber(L, 2)) {
		return 0;
	}
	qry->flags |= lua_tointeger(L, 2);
	return 0;
}

static int query_clear_flag(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	if (lua_gettop(L) < 2 || !lua_isnumber(L, 2)) {
		return 0;
	}
	qry->flags &= ~lua_tointeger(L, 2);
	return 0;
}

static int query_has_flag(lua_State *L)
{
	struct kr_query *qry = lua_touserdata(L, 1);
	if (lua_gettop(L) < 2 || !lua_isnumber(L, 2)) {
		return 0;
	}
	lua_pushboolean(L, qry->flags & lua_tointeger(L, 2));
	return 1;
}

static int query_current(lua_State *L)
{
	struct kr_request *req = lua_touserdata(L, 1);
	lua_pushlightuserdata(L, kr_rplan_current(&req->rplan));
	return 1;
}

int lib_kres(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "query_current",    query_current },
		{ "query_qtype",      query_qtype  },
		{ "query_qclass",     query_qclass },
		{ "query_qname",      query_qname  },
		{ "query_flag",       query_flag   },
		{ "query_clear_flag", query_clear_flag },
		{ "query_has_flag",   query_has_flag },
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
	/* Register packet sections */
	WRAP_CONST(L, ANSWER,     KNOT_);
	WRAP_CONST(L, AUTHORITY,  KNOT_);
	WRAP_CONST(L, ADDITIONAL, KNOT_);
	/* Register RCODE, OPCODE */
	WRAP_LUT(L, "rcode",  knot_rcode_names);
	WRAP_LUT(L, "rrtype", rrtype_names);
	WRAP_LUT(L, "opcode", knot_opcode_names);
	WRAP_LUT(L, "wire",   wire_flag_names);
	WRAP_LUT(L, "query",  query_flag_names);
	/* Register metatables */
	pkt_meta_register(L);
	return 1;	
}
