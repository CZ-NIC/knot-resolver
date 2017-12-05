-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local kres -- the module

local ffi = require('ffi')
local C = ffi.C
local knot = ffi.load(libknot_SONAME)

-- Various declarations that are very stable.
require('kres-gen')

-- Constant tables
local const_class = {
	IN         =   1,
	CH         =   3,
	NONE       = 254,
	ANY        = 255,
}
local const_type = {
	NULL       =   0,
	A          =   1,
	NS         =   2,
	CNAME      =   5,
	SOA        =   6,
	PTR        =  12,
	HINFO      =  13,
	MINFO      =  14,
	MX         =  15,
	TXT        =  16,
	RP         =  17,
	AFSDB      =  18,
	RT         =  21,
	SIG        =  24,
	KEY        =  25,
	AAAA       =  28,
	LOC        =  29,
	SRV        =  33,
	NAPTR      =  35,
	KX         =  36,
	CERT       =  37,
	DNAME      =  39,
	OPT        =  41,
	APL        =  42,
	DS         =  43,
	SSHFP      =  44,
	IPSECKEY   =  45,
	RRSIG      =  46,
	NSEC       =  47,
	DNSKEY     =  48,
	DHCID      =  49,
	NSEC3      =  50,
	NSEC3PARAM =  51,
	TLSA       =  52,
	CDS        =  59,
	CDNSKEY    =  60,
	SPF        =  99,
	NID        = 104,
	L32        = 105,
	L64        = 106,
	LP         = 107,
	EUI48      = 108,
	EUI64      = 109,
	TKEY       = 249,
	TSIG       = 250,
	IXFR       = 251,
	AXFR       = 252,
	ANY        = 255,
}
local const_section = {
	ANSWER     = 0,
	AUTHORITY  = 1,
	ADDITIONAL = 2,
}
local const_rcode = {
	NOERROR    =  0,
	FORMERR    =  1,
	SERVFAIL   =  2,
	NXDOMAIN   =  3,
	NOTIMPL    =  4,
	REFUSED    =  5,
	YXDOMAIN   =  6,
	YXRRSET    =  7,
	NXRRSET    =  8,
	NOTAUTH    =  9,
	NOTZONE    = 10,
	BADVERS    = 16,
	BADCOOKIE  = 23,
}

-- This corresponds to `enum kr_rank`, it's not possible to do this without introspection unfortunately
local const_rank = {
	INITIAL = 0,
	OMIT = 1,
	TRY = 2,
	INDET = 4,
	BOGUS = 5,
	MISMATCH = 6,
	MISSING = 7,
	INSECURE = 8,
	AUTH = 16,
	SECURE = 32
}

-- Create inverse table
local const_rank_tostring = {}
for k, v in pairs(const_rank) do
	const_rank_tostring[v] = k
end

-- Metatype for RR types to allow anonymous types
setmetatable(const_type, {
	__index = function (t, k)
		local v = rawget(t, k)
		if v then return v end
		-- Allow TYPE%d notation
		if string.find(k, 'TYPE', 1, true) then
			return tonumber(k:sub(5))
		end
		-- Unknown type
		return
	end
})

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

-- Metatype for query
local kr_query_t = ffi.typeof('struct kr_query')
ffi.metatype( kr_query_t, {
	__index = {
		name = function(qry) return qry.sname end,
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
			flags = kres.mk_qflags(flags) -- compatibility
			local rplan = C.kr_resolve_plan(req)
			local qry = C.kr_rplan_push(rplan, parent, qname, qclass, qtype)
			if qry ~= nil and flags ~= nil then
				C.kr_qflags_set(qry.flags, flags)
			end
			return qry
		end,
		pop = function(req, qry)
			assert(req)
			return C.kr_rplan_pop(C.kr_resolve_plan(req), qry)
		end,
	},
})

-- C array iterator
local function c_array_iter(t, i)
	i = i + 1
	if i >= t.len then return end
	return i, t.at[i][0]
end

-- Metatype for ranked record array
local ranked_rr_array_t = ffi.typeof('ranked_rr_array_t')
ffi.metatype(ranked_rr_array_t, {
	__len = function(self)
		return tonumber(self.len)
	end,
	__ipairs = function (self)
		return c_array_iter, self, -1
	end,
	__index = {
		get = function (self, i)
			if i < 0 or i > self.len then return nil end
			return self.at[i][0]
		end,
	}
})

--- Pretty print for domain name
local function dname2str(dname)
	return ffi.string(ffi.gc(C.knot_dname_to_str(nil, dname, 0), C.free))
end

-- Pretty-print a single RR (which is a table with .owner .ttl .type .rdata)
-- Extension: append .comment if exists.
local function rr2str(rr, style)
	-- Construct a single-RR temporary set while minimizing copying.
	local rrs = knot_rrset_t()
	knot.knot_rrset_init_empty(rrs)
	rrs._owner = ffi.cast('knot_dname_t *', rr.owner) -- explicit cast needed here
	rrs.type = rr.type
	rrs.rclass = kres.class.IN
	knot.knot_rrset_add_rdata(rrs, rr.rdata, #rr.rdata, rr.ttl, nil)

	local ret = rrs:txt_dump(style)
	C.free(rrs.rrs.data)

	-- Trim the newline and append comment (optionally).
	if ret then
		if ret:byte(-1) == string.byte('\n', -1) then
			ret = ret:sub(1, -2)
		end
		if rr.comment then
			ret = ret .. ' ;' .. rr.comment
		end
	end
	return ret
end

-- Module API
kres = {
	-- Constants
	class = const_class,
	type = const_type,
	section = const_section,
	rcode = const_rcode,
	rank = const_rank,
	rank_tostring = const_rank_tostring,

	-- Create a struct kr_qflags from a single flag name or a list of names.
	mk_qflags = function (names)
		local kr_qflags = ffi.typeof('struct kr_qflags')
		if names == 0 or names == nil then -- compatibility: nil is common in lua
			names = {}
		elseif type(names) == 'string' then
			names = {names}
		elseif ffi.istype(kr_qflags, names) then
			return names
		end

		local fs = ffi.new(kr_qflags)
		for _, name in pairs(names) do
			fs[name] = true
		end
		return fs
	end,

	CONSUME = 1, PRODUCE = 2, DONE = 4, FAIL = 8, YIELD = 16,
	-- Metatypes.  Beware that any pointer will be cast silently...
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
