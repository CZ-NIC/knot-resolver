-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local kres -- the module

local ffi = require('ffi')
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load(libknot_SONAME)

-- Inverse table
local function itable(t, tolower)
	local it = {}
	for k,v in pairs(t) do it[v] = tolower and string.lower(k) or k end
	return it
end

-- Byte order conversions
local function htonl(x) return x end
local htons = htonl
if ffi.abi('le') then
	htonl = bit.bswap
	function htons(x) return bit.rshift(htonl(x), 16) end
end

-- Basic types
local u16_p = ffi.typeof('uint16_t *')

-- Various declarations that are very stable.
ffi.cdef[[
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
void * malloc(size_t size);
void free(void *ptr);
int inet_pton(int af, const char *src, void *dst);
]]

require('kres-gen')

-- Convert libknot error strings
local function knot_strerror(r)
	return ffi.string(knot.knot_strerror(r))
end

-- Constant tables
local const_class = {
	IN         =   1,
	CH         =   3,
	NONE       = 254,
	ANY        = 255,
}
local const_type = {
	A          =   1,
	NS         =   2,
	MD         =   3,
	MF         =   4,
	CNAME      =   5,
	SOA        =   6,
	MB         =   7,
	MG         =   8,
	MR         =   9,
	NULL       =  10,
	WKS        =  11,
	PTR        =  12,
	HINFO      =  13,
	MINFO      =  14,
	MX         =  15,
	TXT        =  16,
	RP         =  17,
	AFSDB      =  18,
	X25        =  19,
	ISDN       =  20,
	RT         =  21,
	NSAP       =  22,
	['NSAP-PTR']   =  23,
	SIG        =  24,
	KEY        =  25,
	PX         =  26,
	GPOS       =  27,
	AAAA       =  28,
	LOC        =  29,
	NXT        =  30,
	EID        =  31,
	NIMLOC     =  32,
	SRV        =  33,
	ATMA       =  34,
	NAPTR      =  35,
	KX         =  36,
	CERT       =  37,
	A6         =  38,
	DNAME      =  39,
	SINK       =  40,
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
	SMIMEA     =  53,
	HIP        =  55,
	NINFO      =  56,
	RKEY       =  57,
	TALINK     =  58,
	CDS        =  59,
	CDNSKEY    =  60,
	OPENPGPKEY =  61,
	CSYNC      =  62,
	SPF        =  99,
	UINFO      = 100,
	UID        = 101,
	GID        = 102,
	UNSPEC     = 103,
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
	MAILB      = 253,
	MAILA      = 254,
	ANY        = 255,
	URI        = 256,
	CAA        = 257,
	AVC        = 258,
	DOA        = 259,
	TA         = 32768,
	DLV        = 32769,
}
local const_section = {
	ANSWER     = 0,
	AUTHORITY  = 1,
	ADDITIONAL = 2,
}
local const_opcode = {
	QUERY      = 0,
	IQUERY     = 1,
	STATUS     = 2,
	NOTIFY     = 4,
	UPDATE     = 5,
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

-- Constant tables
local const_class_str = itable(const_class)
local const_type_str = itable(const_type)
local const_rcode_str = itable(const_rcode)
local const_opcode_str = itable(const_opcode)
local const_section_str = itable(const_section)
local const_rank_str = itable(const_rank)

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

-- Metatype for RR types to allow anonymous string types
setmetatable(const_type_str, {
	__index = function (t, k)
		local v = rawget(t, k)
		if v then return v end
		return string.format('TYPE%d', k)
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
		port = function (sa) return C.kr_inaddr_port(sa) end,
	}
})

-- Pretty print for domain name
local function dname2str(dname)
	return ffi.string(ffi.gc(C.knot_dname_to_str(nil, dname, 0), C.free))
end

-- Convert dname pointer to wireformat string
local function dname2wire(name)
	if name == nil then return end
	return ffi.string(name, knot.knot_dname_size(name))
end

-- RR sets created in Lua must have a destructor to release allocated memory
local function rrset_free(rr)
	if rr._owner ~= nil then ffi.C.free(rr._owner) end
	if rr.rrs.rr_count > 0 then ffi.C.free(rr.rrs.data) end
end

-- Metatype for RR set.  Beware, the indexing is 0-based (rdata, get, tostring).
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new('char[?]', rrset_buflen)
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	-- Create a new empty RR set object with an allocated owner and a destructor
	__new = function (ct, owner, rrtype, rrclass)
		local rr = ffi.new(ct)
		knot.knot_rrset_init_empty(rr)
		rr._owner = owner and knot.knot_dname_copy(owner, nil)
		rr.type = rrtype or 0
		rr.rclass = rrclass or const_class.IN
		return ffi.gc(rr, rrset_free)
	end,
	-- beware: `owner` and `rdata` are typed as a plain lua strings
	--         and not the real types they represent.
	__tostring = function(rr) return rr:txt_dump() end,
	__index = {
		owner = function(rr) return dname2wire(rr._owner) end,
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
					ret = -1
				end
				return ret >= 0 and ffi.string(rrset_buf)
			end
		end,

		-- Dump the rrset in presentation format (dig-like).
		txt_dump = function(rr, style)
			local bufsize = 1024
			local dump = ffi.new('char *[1]', C.malloc(bufsize))
				-- ^ one pointer to a string
			local size = ffi.new('size_t[1]', { bufsize }) -- one size_t = bufsize

			local ret = knot.knot_rrset_txt_dump(rr, dump, size,
							style or knot.KNOT_DUMP_STYLE_DEFAULT)
			local result = nil
			if ret >= 0 then
				result = ffi.string(dump[0], ret)
			end
			C.free(dump[0])
			return result
		end,
		-- Add binary RDATA to the RR set
		add_rdata = function (rr, rdata, rdlen, ttl)
			assert(ffi.istype(knot_rrset_t, rr))
			local ret = knot.knot_rrset_add_rdata(rr, rdata, tonumber(rdlen), tonumber(ttl or 0), nil)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
	},
})

-- Destructor for packet accepts pointer to pointer
local packet_ptr = ffi.new('knot_pkt_t *[1]')
local function pkt_free(pkt)
	packet_ptr[0] = pkt
	knot.knot_pkt_free(packet_ptr)
end

-- Helpers for reading/writing 16-bit numbers from packet wire
local function pkt_u16(pkt, off, val)
	local ptr = ffi.cast(u16_p, pkt.wire + off)
	if val ~= nil then ptr[0] = htons(val) end
	return (htons(ptr[0]))
end

-- Helpers for reading/writing message header flags
local function pkt_bit(pkt, byteoff, bitmask, val)
	-- If the value argument is passed, set/clear the desired bit
	if val ~= nil then
		if val then pkt.wire[byteoff] = bit.bor(pkt.wire[byteoff], bitmask)
		else pkt.wire[byteoff] = bit.band(pkt.wire[byteoff], bit.bnot(bitmask)) end
		return true
	end
	return (bit.band(pkt.wire[byteoff], bitmask) ~= 0)
end

-- Helpers for converting packet to text
local function section_tostring(pkt, section_id)
	local data = {}
	local section = knot.knot_pkt_section(pkt, section_id)
	if section.count > 0 then
		table.insert(data, string.format('\n;; %s\n', const_section_str[section_id]))
		for j = 0, section.count - 1 do
			local rrset = knot.knot_pkt_rr(section, j)
			local rrtype = rrset.type
			if rrtype ~= const_type.OPT and rrtype ~= const_type.TSIG then
				table.insert(data, rrset:txt_dump())
			end
		end
	end
	return table.concat(data, '')
end

local function packet_tostring(pkt)
	local hdr = string.format(';; ->>HEADER<<- opcode: %s; status: %s; id: %d\n',
		const_opcode_str[pkt:opcode()], const_rcode_str[pkt:rcode()], pkt:id())
	local flags = {}
	for _,v in ipairs({'rd', 'tc', 'aa', 'qr', 'cd', 'ad', 'ra'}) do
		if(pkt[v](pkt)) then table.insert(flags, v) end
	end
	local info = string.format(';; Flags: %s; QUERY: %d; ANSWER: %d; AUTHORITY: %d; ADDITIONAL: %d\n',
		table.concat(flags, ' '), pkt:qdcount(), pkt:ancount(), pkt:nscount(), pkt:arcount())
	local data = '\n'
	if pkt.opt_rr ~= nil then
		data = data..string.format(';; OPT PSEUDOSECTION:\n%s', pkt.opt_rr:tostring())
	end
	if pkt.tsig_rr ~= nil then
		data = data..string.format(';; TSIG PSEUDOSECTION:\n%s', pkt.tsig_rr:tostring())
	end
	-- Zone transfer answers may omit question
	if pkt:qdcount() > 0 then
		data = data..string.format(';; QUESTION\n;; %s\t%s\t%s\n',
			dname2str(pkt:qname()), const_type_str[pkt:qtype()], const_class_str[pkt:qclass()])
	end
	local data_sec = {}
	for i = const_section.ANSWER, const_section.ADDITIONAL do
		table.insert(data_sec, section_tostring(pkt, i))
	end
	return hdr..info..data..table.concat(data_sec, '')
end

-- Metatype for packet
local knot_pkt_t = ffi.typeof('knot_pkt_t')
ffi.metatype( knot_pkt_t, {
	__new = function (_, size, wire)
		if size < 12 or size > 65535 then
			error('packet size must be <12, 65535>')
		end

		local pkt = knot.knot_pkt_new(nil, size, nil)
		if pkt == nil then
			error(string.format('failed to allocate a packet of size %d', size))
		end
		if wire == nil then
			pkt:id(tonumber(C.kr_rand_uint(65535)))
		else
			assert(size <= #wire)
			ffi.copy(pkt.wire, wire, size)
			pkt.size = size
			pkt.parsed = 0
		end

		return ffi.gc(pkt[0], pkt_free)
	end,
	__tostring = function(pkt)
		return pkt:tostring()
	end,
	__len = function(pkt)
		assert(pkt ~= nil) return pkt.size
	end,
	__ipairs = function(self)
		return ipairs(self:section(const_section.ANSWER))
	end,
	__index = {
		-- Header
		id      = function(pkt, val) return pkt_u16(pkt, 0,  val) end,
		qdcount = function(pkt, val) return pkt_u16(pkt, 4,  val) end,
		ancount = function(pkt, val) return pkt_u16(pkt, 6,  val) end,
		nscount = function(pkt, val) return pkt_u16(pkt, 8,  val) end,
		arcount = function(pkt, val) return pkt_u16(pkt, 10, val) end,
		opcode = function (pkt, val)
			assert(pkt ~= nil)
			pkt.wire[2] = (val) and bit.bor(bit.band(pkt.wire[2], 0x78), 8 * val) or pkt.wire[2]
			return (bit.band(pkt.wire[2], 0x78) / 8)
		end,
		rcode = function (pkt, val)
			pkt.wire[3] = (val) and bor(band(pkt.wire[3], 0xf0), val) or pkt.wire[3]
			return band(pkt.wire[3], 0x0f)
		end,
		rd = function (pkt, val) return pkt_bit(pkt, 2, 0x01, val) end,
		tc = function (pkt, val) return pkt_bit(pkt, 2, 0x02, val) end,
		aa = function (pkt, val) return pkt_bit(pkt, 2, 0x04, val) end,
		qr = function (pkt, val) return pkt_bit(pkt, 2, 0x80, val) end,
		cd = function (pkt, val) return pkt_bit(pkt, 3, 0x10, val) end,
		ad = function (pkt, val) return pkt_bit(pkt, 3, 0x20, val) end,
		ra = function (pkt, val) return pkt_bit(pkt, 3, 0x80, val) end,
		-- Question
		qname = function(pkt)
			local qname = knot.knot_pkt_qname(pkt)
			return dname2wire(qname)
		end,
		qclass = function(pkt) return knot.knot_pkt_qclass(pkt) end,
		qtype  = function(pkt) return knot.knot_pkt_qtype(pkt) end,
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
		begin = function (pkt, section)
			assert(pkt ~= nil)
			assert(section >= pkt.current, 'cannot rewind to already written section')
			assert(const_section_str[section], string.format('invalid section: %s', section))
			local ret = knot.knot_pkt_begin(pkt, section)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
		put = function (pkt, owner, ttl, rclass, rtype, rdata)
			assert(pkt ~= nil)
			local ret = C.kr_pkt_put(pkt, owner, ttl, rclass, rtype, rdata, #rdata)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
		recycle = function (pkt)
			assert(pkt ~= nil)
			local ret = C.kr_pkt_recycle(pkt)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
		clear_payload = function (pkt)
			assert(pkt ~= nil)
			local ret = C.kr_pkt_clear_payload(pkt)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
		question = function(pkt, qname, qclass, qtype)
			assert(pkt ~= nil)
			assert(qclass ~= nil, string.format('invalid class: %s', qclass))
			assert(qtype ~= nil, string.format('invalid type: %s', qtype))
			local ret = C.knot_pkt_put_question(pkt, qname, qclass, qtype)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
		towire = function (pkt)
			return ffi.string(pkt.wire, pkt.size)
		end,
		tostring = function(pkt)
			return packet_tostring(pkt)
		end,
		-- Packet manipulation
		parse = function (pkt)
			assert(pkt ~= nil)
			local ret = knot.knot_pkt_parse(pkt, 0)
			if ret ~= 0 then return nil, knot_strerror(ret) end
			return true
		end,
	},
})
-- Metatype for query
local kr_query_t = ffi.typeof('struct kr_query')
ffi.metatype( kr_query_t, {
	__index = {
		name = function(qry) return dname2wire(qry.sname) end,
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
		-- returns first resolved sub query for a request
		first_resolved = function(req)
			assert(req)
			local rplan = C.kr_resolve_plan(req)
			if not rplan or rplan.resolved.len < 1 then return nil end
			return rplan.resolved.at[0]
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

-- Pretty-print a single RR (which is a table with .owner .ttl .type .rdata)
-- Extension: append .comment if exists.
local function rr2str(rr, style)
	-- Construct a single-RR temporary set while minimizing copying.
	local ret
	do
		local rrs = knot_rrset_t(rr.owner, rr.type, kres.class.IN)
		rrs:add_rdata(rr.rdata, #rr.rdata, rr.ttl)
		ret = rrs:txt_dump(style)
	end

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
	opcode = const_opcode,
	rank = const_rank,

	-- Constants to strings
	tostring = {
		class = const_class_str,
		type = const_type_str,
		section = const_section_str,
		rcode = const_rcode_str,
		opcode = const_opcode_str,
		rank = const_rank_str,
	},

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

	-- Export types
	rrset = knot_rrset_t,
	packet = knot_pkt_t,

	-- Metatypes.  Beware that any pointer will be cast silently...
	pkt_t = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	request_t = function (udata) return ffi.cast('struct kr_request *', udata) end,
	-- Global API functions
	str2dname = function(name)
		local dname = ffi.gc(C.knot_dname_from_str(nil, name, 0), C.free)
		return dname2wire(dname)
	end,
	dname2str = dname2str,
	dname2wire = dname2wire,
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
