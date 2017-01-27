-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

ffi = require('ffi')
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load(libknot_SONAME)

-- Various declarations that are very stable.
ffi.cdef[[

/*
 * Record types and classes.
 */
struct rr_class {
	static const int IN         =   1;
	static const int CH         =   3;
	static const int NONE       = 254;
	static const int ANY        = 255;
};
struct rr_type {
	static const int A          =   1;
	static const int NS         =   2;
	static const int CNAME      =   5;
	static const int SOA        =   6;
	static const int PTR        =  12;
	static const int HINFO      =  13;
	static const int MINFO      =  14;
	static const int MX         =  15;
	static const int TXT        =  16;
	static const int RP         =  17;
	static const int AFSDB      =  18;
	static const int RT         =  21;
	static const int SIG        =  24;
	static const int KEY        =  25;
	static const int AAAA       =  28;
	static const int LOC        =  29;
	static const int SRV        =  33;
	static const int NAPTR      =  35;
	static const int KX         =  36;
	static const int CERT       =  37;
	static const int DNAME      =  39;
	static const int OPT        =  41;
	static const int APL        =  42;
	static const int DS         =  43;
	static const int SSHFP      =  44;
	static const int IPSECKEY   =  45;
	static const int RRSIG      =  46;
	static const int NSEC       =  47;
	static const int DNSKEY     =  48;
	static const int DHCID      =  49;
	static const int NSEC3      =  50;
	static const int NSEC3PARAM =  51;
	static const int TLSA       =  52;
	static const int CDS        =  59;
	static const int CDNSKEY    =  60;
	static const int SPF        =  99;
	static const int NID        = 104;
	static const int L32        = 105;
	static const int L64        = 106;
	static const int LP         = 107;
	static const int EUI48      = 108;
	static const int EUI64      = 109;
	static const int TKEY       = 249;
	static const int TSIG       = 250;
	static const int IXFR       = 251;
	static const int AXFR       = 252;
	static const int ANY        = 255;
};
struct pkt_section {
	static const int ANSWER     = 0;
	static const int AUTHORITY  = 1;
	static const int ADDITIONAL = 2;
};
struct pkt_rcode {
	static const int NOERROR    =  0;
	static const int FORMERR    =  1;
	static const int SERVFAIL   =  2;
	static const int NXDOMAIN   =  3;
	static const int NOTIMPL    =  4;
	static const int REFUSED    =  5;
	static const int YXDOMAIN   =  6;
	static const int YXRRSET    =  7;
	static const int NXRRSET    =  8;
	static const int NOTAUTH    =  9;
	static const int NOTZONE    = 10;
	static const int BADVERS    = 16;
};

/*
 * Data structures
 */

/* stdlib */
typedef long time_t;
struct timeval {
	time_t tv_sec;
	time_t tv_usec;
};
struct sockaddr {
    uint16_t sa_family;
    uint8_t _stub[]; /* Do not touch */
};

/*
 * libc APIs
 */
void free(void *ptr);
int inet_pton(int af, const char *src, void *dst);
]]

require('kres-gen')

-- Constants
local query_flag = ffi.new('struct query_flag')

-- Metatype for sockaddr
local addr_buf = ffi.new('char[16]')
local sockaddr_t = ffi.typeof('struct sockaddr')
ffi.metatype( sockaddr_t, {
	__index = {
		len = function(sa) return C.kr_inaddr_len(sa) end,
		ip = function (sa) return C.kr_inaddr(sa) end,
		family = function (sa) return C.kr_inaddr_family(sa) end,
	}
})

-- Metatype for RR set
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new('char[?]', rrset_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	__index = {
		owner = function(rr) return ffi.string(rr._owner, knot.knot_dname_size(rr._owner)) end,
		ttl = function(rr) return tonumber(knot.knot_rrset_ttl(rr)) end,
		rdata = function(rr, i)
			local rdata = knot.knot_rdataset_at(rr.rrs, i)
			return ffi.string(knot.knot_rdata_data(rdata), knot.knot_rdata_rdlen(rdata))
		end,
		get = function(rr, i)
			return {owner = rr:owner(),
			        ttl = rr:ttl(),
			        class = tonumber(rr.rclass),
			        type = tonumber(rr.type),
			        rdata = rr:rdata(i)}
		end,
		tostring = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr.rrs.rr_count > 0 then
				local ret
				if i ~= nil then
					ret = knot.knot_rrset_txt_dump_data(rr, i, rrset_buf, rrset_buflen, knot.KNOT_DUMP_STYLE_DEFAULT)
				else
					ret = knot.knot_rrset_txt_dump(rr, rrset_buf, rrset_buflen, knot.KNOT_DUMP_STYLE_DEFAULT)
				end
				return ret >= 0 and ffi.string(rrset_buf)
			end
		end,
	}
})

-- Metatype for packet
local knot_pkt_t = ffi.typeof('knot_pkt_t')
ffi.metatype( knot_pkt_t, {
	__index = {
		qname = function(pkt)
			local qname = knot.knot_pkt_qname(pkt)
			return ffi.string(qname, knot.knot_dname_size(qname))
		end,
		qclass = function(pkt) return knot.knot_pkt_qclass(pkt) end,
		qtype  = function(pkt) return knot.knot_pkt_qtype(pkt) end,
		rcode = function (pkt, val)
			pkt.wire[3] = (val) and bor(band(pkt.wire[3], 0xf0), val) or pkt.wire[3]
			return band(pkt.wire[3], 0x0f)
		end,
		tc = function (pkt, val)
			pkt.wire[2] = bor(pkt.wire[2], (val) and 0x02 or 0x00)
			return band(pkt.wire[2], 0x02)
		end,
		rrsets = function (pkt, section_id)
			local records = {}
			local section = knot.knot_pkt_section(pkt, section_id)
			for i = 1, section.count do
				local rrset = knot.knot_pkt_rr(section, i - 1)
				table.insert(records, rrset)
			end
			return records
		end,
		section = function (pkt, section_id)
			local records = {}
			local section = knot.knot_pkt_section(pkt, section_id)
			for i = 1, section.count do
				local rrset = knot.knot_pkt_rr(section, i - 1)
				for k = 1, rrset.rrs.rr_count do
					table.insert(records, rrset:get(k - 1))
				end
			end
			return records
		end, 
		begin = function (pkt, section) return knot.knot_pkt_begin(pkt, section) end,
		put = function (pkt, owner, ttl, rclass, rtype, rdata)
			return C.kr_pkt_put(pkt, owner, ttl, rclass, rtype, rdata, #rdata)
		end,
		clear = function (pkt) return C.kr_pkt_recycle(pkt) end,
		question = function(pkt, qname, qclass, qtype)
			return C.knot_pkt_put_question(pkt, qname, qclass, qtype)
		end,
	},
})
-- Metatype for query
local ub_t = ffi.typeof('unsigned char *')
local kr_query_t = ffi.typeof('struct kr_query')
ffi.metatype( kr_query_t, {
	__index = {
		name = function(qry) return ffi.string(qry.sname, knot.knot_dname_size(qry.sname)) end,
		hasflag = function(qry, flag)
			return band(qry.flags, flag) ~= 0
		end,
		resolved = function(qry)
			return qry:hasflag(query_flag.RESOLVED)
		end,
		final = function(qry)
			return qry:resolved() and (qry.parent == nil)
		end,
		nslist = function(qry, list)
			assert(#list <= 4, 'maximum of 4 addresses can be evaluated for each query')
			for i, ns in ipairs(list) do
				assert(C.kr_nsrep_set(qry, i - 1, ns) == 0);
			end
			-- If less than maximum NSs, insert guard to terminate the list
			if #list < 4 then
				assert(C.kr_nsrep_set(qry, #list, nil) == 0);
			end
		end,
	},
})
-- Metatype for request
local kr_request_t = ffi.typeof('struct kr_request')
ffi.metatype( kr_request_t, {
	__index = {
		current = function(req)
			assert(req)
			if req.current_query == nil then return nil end
			return req.current_query
		end,
		resolved = function(req)
			assert(req)
			local qry = C.kr_rplan_resolved(C.kr_resolve_plan(req))
			if qry == nil then return nil end
			return qry

		end,
		push = function(req, qname, qtype, qclass, flags, parent)
			assert(req)
			local rplan = C.kr_resolve_plan(req)
			local qry = C.kr_rplan_push(rplan, parent, qname, qclass, qtype)
			if qry ~= nil and flags ~= nil then
				qry.flags = bor(qry.flags, flags)
			end
			return qry
		end,
		pop = function(req, qry)
			assert(req)
			return C.kr_rplan_pop(C.kr_resolve_plan(req), qry)
		end,
	},
})

-- Pretty print for domain name
local function dname2str(dname)
	return ffi.string(ffi.gc(C.knot_dname_to_str(nil, dname, 0), C.free))
end

-- Pretty print for RR
local function rr2str(rr)
	local function hex_encode(str)
		return (str:gsub('.', function (c)
			return string.format('%02X', string.byte(c))
		end))
	end
	local rdata = hex_encode(rr.rdata)
	return string.format('%s %d IN TYPE%d \\# %d %s',
		dname2str(rr.owner), rr.ttl, rr.type, #rr.rdata, rdata)
end

-- Module API
local kres = {
	-- Constants
	class = ffi.new('struct rr_class'),
	type = ffi.new('struct rr_type'),
	section = ffi.new('struct pkt_section'),
	rcode = ffi.new('struct pkt_rcode'),
	query = query_flag,
	CONSUME = 1, PRODUCE = 2, DONE = 4, FAIL = 8, YIELD = 16,
	-- Metatypes
	pkt_t = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	request_t = function (udata) return ffi.cast('struct kr_request *', udata) end,
	-- Global API functions
	str2dname = function(name)
		local dname = ffi.gc(C.knot_dname_from_str(nil, name, 0), C.free)
		return ffi.string(dname, knot.knot_dname_size(dname))
	end,
	dname2str = dname2str,
	rr2str = rr2str,
	str2ip = function (ip)
		local family = C.kr_straddr_family(ip)
		local ret = C.inet_pton(family, ip, addr_buf)
		if ret ~= 1 then return nil end
		return ffi.string(addr_buf, C.kr_family_len(family))
	end,
	context = function () return ffi.cast('struct kr_context *', __engine) end,
}

return kres
