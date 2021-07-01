-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- SPDX-License-Identifier: GPL-3.0-or-later
--
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

struct knot_error {
	int code;
};

/*
 * libc APIs
 */
void * malloc(size_t size);
void free(void *ptr);
int inet_pton(int af, const char *src, void *dst);
int gettimeofday(struct timeval *tv, struct timezone *tz);
]]

require('kres-gen')

-- Error code representation
local knot_error_t = ffi.typeof('struct knot_error')
ffi.metatype(knot_error_t, {
	-- Convert libknot error strings
	__tostring = function(self)
		return ffi.string(knot.knot_strerror(self.code))
	end,
});

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

-- Metatype for timeval
local timeval_t = ffi.typeof('struct timeval')

-- Metatype for sockaddr
local addr_buf = ffi.new('char[16]')
local str_addr_buf = ffi.new('char[46 + 1 + 6 + 1]') -- INET6_ADDRSTRLEN + #port + \0
local str_addr_buf_len = ffi.sizeof(str_addr_buf)
local sockaddr_t = ffi.typeof('struct sockaddr')
ffi.metatype( sockaddr_t, {
	__index = {
		len = function(sa) return C.kr_inaddr_len(sa) end,
		ip = function (sa) return C.kr_inaddr(sa) end,
		family = function (sa) return C.kr_inaddr_family(sa) end,
		port = function (sa) return C.kr_inaddr_port(sa) end,
	},
	__tostring = function(sa)
		assert(ffi.istype(sockaddr_t, sa))
		local len = ffi.new('size_t[1]', str_addr_buf_len)
		local ret = C.kr_inaddr_str(sa, str_addr_buf, len)
		if ret ~= 0 then
			error('kr_inaddr_str failed: ' .. tostring(ret))
		end
		return ffi.string(str_addr_buf)
	end,

})

-- Parametrized LRU table
local typed_lru_t = 'struct { $ value_type[1]; struct lru * lru; }'

-- Metatype for LRU
local lru_metatype = {
	-- Create a new LRU with given value type
	-- By default the LRU will have a capacity of 65536 elements
	-- Note: At the point the parametrized type must be finalized
	__new = function (ct, max_slots, alignment)
		-- {0} will make sure that the value is coercible to a number
		local o = ffi.new(ct, {0}, C.lru_create_impl(max_slots or 65536, alignment or 1, nil, nil))
		if o.lru == nil then
			return
		end
		return o
	end,
	-- Destructor to clean allocated memory
	__gc = function (self)
		assert(self.lru ~= nil)
		C.lru_free_items_impl(self.lru)
		C.free(self.lru)
		self.lru = nil
	end,
	__index = {
		-- Look up key and return reference to current
		-- Note: The key will be inserted if it doesn't exist
		get_ref = function (self, key, key_len, allow_insert)
			local insert = allow_insert and true or false
			local ptr = C.lru_get_impl(self.lru, key, key_len or #key, ffi.sizeof(self.value_type[0]), insert, nil)
			if ptr ~= nil then
				return ffi.cast(self.value_type, ptr)
			end
		end,
		-- Look up key and return current value
		get = function (self, key, key_len)
			local ref = self:get_ref(key, key_len, false)
			if ref then
				return ref[0]
			end
		end,
		-- Set value for key to given value
		set = function (self, key, value, key_len)
			local ref = self:get_ref(key, key_len, true)
			if ref then
				ref[0] = value
				return true
			end
		end,
	},
}

-- Pretty print for domain name
local function dname2str(dname)
	if dname == nil then return end
	local text_name = ffi.gc(C.knot_dname_to_str(nil, dname, 0), C.free)
	if text_name ~= nil then
		return ffi.string(text_name)
	end
end

-- Convert dname pointer to wireformat string
local function dname2wire(name)
	if name == nil then return nil end
	return ffi.string(name, knot.knot_dname_size(name))
end

-- RR sets created in Lua must have a destructor to release allocated memory
local function rrset_free(rr)
	if rr._owner ~= nil then ffi.C.free(rr._owner) end
	if rr:rdcount() > 0 then ffi.C.free(rr.rrs.rdata) end
end

-- Metatype for RR set.  Beware, the indexing is 0-based (rdata, get, tostring).
local rrset_buflen = (64 + 1) * 1024
local rrset_buf = ffi.new('char[?]', rrset_buflen)
local knot_rrset_pt = ffi.typeof('knot_rrset_t *')
local knot_rrset_t = ffi.typeof('knot_rrset_t')
ffi.metatype( knot_rrset_t, {
	-- Create a new empty RR set object with an allocated owner and a destructor
	__new = function (ct, owner, rrtype, rrclass, ttl)
		local rr = ffi.new(ct)
		C.kr_rrset_init(rr,
			owner and knot.knot_dname_copy(owner, nil),
			rrtype or 0,
			rrclass or const_class.IN,
			ttl or 0)
		return ffi.gc(rr, rrset_free)
	end,
	-- BEWARE: `owner` and `rdata` are typed as a plain lua strings
	--         and not the real types they represent.
	__tostring = function(rr)
		assert(ffi.istype(knot_rrset_t, rr))
		return rr:txt_dump()
	end,
	__index = {
		owner = function(rr)
			assert(ffi.istype(knot_rrset_t, rr))
			return dname2wire(rr._owner)
		end,
		ttl = function(rr)
			assert(ffi.istype(knot_rrset_t, rr))
			return tonumber(rr._ttl)
		end,
		class = function(rr, val)
			assert(ffi.istype(knot_rrset_t, rr))
			if val then
				rr.rclass = val
			end
			return tonumber(rr.rclass)
		end,
		rdata_pt = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr) and i >= 0 and i < rr:rdcount())
			return knot.knot_rdataset_at(rr.rrs, i)
		end,
		rdata = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			local rd = rr:rdata_pt(i)
			return ffi.string(rd.data, rd.len)
		end,
		get = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr) and i >= 0 and i < rr:rdcount())
			return {owner = rr:owner(),
			        ttl = rr:ttl(),
			        class = tonumber(rr.rclass),
			        type = tonumber(rr.type),
			        rdata = rr:rdata(i)}
		end,
		tostring = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr)
					and (i == nil or (i >= 0 and i < rr:rdcount())) )
			if rr:rdcount() > 0 then
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
			assert(ffi.istype(knot_rrset_t, rr))
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
		txt_fields = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(i >= 0 and i < rr:rdcount())
			local bufsize = 1024
			local dump = ffi.new('char *', C.malloc(bufsize))
			ffi.gc(dump, C.free)

			local ret = knot.knot_rrset_txt_dump_data(rr, i, dump, 1024,
							knot.KNOT_DUMP_STYLE_DEFAULT)
			if ret >= 0 then
				local out = {}
				out.owner = dname2str(rr:owner())
				out.ttl = rr:ttl()
				out.class = kres.tostring.class[rr:class()]
				out.type = kres.tostring.type[rr.type]
				out.rdata = ffi.string(dump, ret)
				return out
			else
				panic('knot_rrset_txt_dump_data failure ' .. tostring(ret))
			end
		end,
		-- Return RDATA count for this RR set
		rdcount = function(rr)
			assert(ffi.istype(knot_rrset_t, rr))
			return tonumber(rr.rrs.count)
		end,
		-- Add binary RDATA to the RR set
		add_rdata = function (rr, rdata, rdlen, no_ttl)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(no_ttl == nil, 'add_rdata() can not accept TTL anymore')
			local ret = knot.knot_rrset_add_rdata(rr, rdata, tonumber(rdlen), nil)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		-- Merge data from another RR set into the current one
		merge_rdata = function (rr, source)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(ffi.istype(knot_rrset_t, source))
			local ret = knot.knot_rdataset_merge(rr.rrs, source.rrs, nil)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		-- Return type covered by this RRSIG
		type_covered = function(rr, i)
			i = i or 0
			assert(ffi.istype(knot_rrset_t, rr) and i >= 0 and i < rr:rdcount())
			if rr.type ~= const_type.RRSIG then return end
			return tonumber(C.kr_rrsig_type_covered(knot.knot_rdataset_at(rr.rrs, i)))
		end,
		-- Check whether a RRSIG is covering current RR set
		is_covered_by = function(rr, rrsig)
			assert(ffi.istype(knot_rrset_t, rr))
			assert(ffi.istype(knot_rrset_t, rrsig))
			assert(rrsig.type == const_type.RRSIG)
			return (rr.type == rrsig:type_covered() and rr:owner() == rrsig:owner())
		end,
		-- Return RR set wire size
		wire_size = function(rr)
			assert(ffi.istype(knot_rrset_t, rr))
			return tonumber(knot.knot_rrset_size(rr))
		end,
	},
})

-- Destructor for packet accepts pointer to pointer
local knot_pkt_t = ffi.typeof('knot_pkt_t')

-- Helpers for reading/writing 16-bit numbers from packet wire
local function pkt_u16(pkt, off, val)
	assert(ffi.istype(knot_pkt_t, pkt))
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

local function knot_pkt_rr(section, i)
	assert(section and ffi.istype('knot_pktsection_t', section)
			and i >= 0 and i < section.count)
	local ret = section.pkt.rr + section.pos + i
	assert(ffi.istype(knot_rrset_pt, ret))
	return ret
end

-- Metatype for packet
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
			C.kr_rnd_buffered(pkt.wire, 2) -- randomize the query ID
		else
			assert(size <= #wire)
			ffi.copy(pkt.wire, wire, size)
			pkt.size = size
			pkt.parsed = 0
		end

		return ffi.gc(pkt[0], knot.knot_pkt_free)
	end,
	__tostring = function(pkt)
		return pkt:tostring()
	end,
	__len = function(pkt)
		assert(ffi.istype(knot_pkt_t, pkt))
		return tonumber(pkt.size)
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
			assert(ffi.istype(knot_pkt_t, pkt))
			pkt.wire[2] = (val) and bit.bor(bit.band(pkt.wire[2], 0x78), 8 * val) or pkt.wire[2]
			return (bit.band(pkt.wire[2], 0x78) / 8)
		end,
		rcode = function (pkt, val)
			assert(ffi.istype(knot_pkt_t, pkt))
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
		-- "do" is a reserved word in Lua; only getter
		dobit = function(pkt, val)
			assert(val == nil, 'dobit is getter only')
			assert(ffi.istype(knot_pkt_t, pkt))
			return C.kr_pkt_has_dnssec(pkt)
		end,
		-- Question
		qname = function(pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			-- inlined knot_pkt_qname(), basically
			if pkt == nil or pkt.qname_size == 0 then return nil end
			return ffi.string(pkt.wire + 12, pkt.qname_size)
		end,
		qclass = function(pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			return C.kr_pkt_qclass(pkt)
		end,
		qtype  = function(pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			return C.kr_pkt_qtype(pkt)
		end,
		rrsets = function (pkt, section_id)
			assert(ffi.istype(knot_pkt_t, pkt))
			local records = {}
			local section = pkt.sections + section_id
			for i = 1, section.count do
				local rrset = knot_pkt_rr(section, i - 1)
				table.insert(records, rrset)
			end
			return records
		end,
		section = function (pkt, section_id)
			assert(ffi.istype(knot_pkt_t, pkt))
			local records = {}
			local section = pkt.sections + section_id
			for i = 1, section.count do
				local rrset = knot_pkt_rr(section, i - 1)
				for k = 1, rrset:rdcount() do
					table.insert(records, rrset:get(k - 1))
				end
			end
			return records
		end,
		begin = function (pkt, section)
			assert(ffi.istype(knot_pkt_t, pkt))
			assert(section >= pkt.current, 'cannot rewind to already written section')
			assert(const_section_str[section], string.format('invalid section: %s', section))
			local ret = knot.knot_pkt_begin(pkt, section)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		put = function (pkt, owner, ttl, rclass, rtype, rdata)
			assert(ffi.istype(knot_pkt_t, pkt))
			local ret = C.kr_pkt_put(pkt, owner, ttl, rclass, rtype, rdata, #rdata)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		-- Put an RR set in the packet
		-- Note: the packet doesn't take ownership of the RR set
		put_rr = function (pkt, rr, rotate, flags)
			assert(ffi.istype(knot_pkt_t, pkt))
			assert(ffi.istype(knot_rrset_t, rr))
			local ret = C.knot_pkt_put_rotate(pkt, 0, rr, rotate or 0, flags or 0)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		recycle = function (pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			local ret = C.kr_pkt_recycle(pkt)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		clear_payload = function (pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			local ret = C.kr_pkt_clear_payload(pkt)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		question = function(pkt, qname, qclass, qtype)
			assert(ffi.istype(knot_pkt_t, pkt))
			assert(qclass ~= nil, string.format('invalid class: %s', qclass))
			assert(qtype ~= nil, string.format('invalid type: %s', qtype))
			local ret = C.knot_pkt_put_question(pkt, qname, qclass, qtype)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		towire = function (pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			return ffi.string(pkt.wire, pkt.size)
		end,
		tostring = function(pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			return ffi.string(ffi.gc(C.kr_pkt_text(pkt), C.free))
		end,
		-- Return number of remaining empty bytes in the packet
		-- This is generally useful to check if there's enough space
		remaining_bytes = function (pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			local occupied = pkt.size + pkt.reserved
			assert(pkt.max_size >= occupied)
			return tonumber(pkt.max_size - occupied)
		end,
		-- Packet manipulation
		parse = function (pkt)
			assert(ffi.istype(knot_pkt_t, pkt))
			local ret = knot.knot_pkt_parse(pkt, 0)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		-- Resize packet wire to a new size
		resize = function (pkt, new_size)
			assert(ffi.istype(knot_pkt_t, pkt))
			local ptr = C.mm_realloc(pkt.mm, pkt.wire, new_size, pkt.max_size)
			if ptr == nil then return end
			pkt.wire = ptr
			pkt.max_size = new_size
			return true
		end,
	},
})
-- Metatype for query
local kr_query_t = ffi.typeof('struct kr_query')
ffi.metatype( kr_query_t, {
	__index = {
		-- Return query domain name
		name = function(qry)
			assert(ffi.istype(kr_query_t, qry))
			return dname2wire(qry.sname)
		end,
		-- Write this query into packet
		write = function(qry, pkt)
			assert(ffi.istype(kr_query_t, qry))
			assert(ffi.istype(knot_pkt_t, pkt))
			local ret = C.kr_make_query(qry, pkt)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
	},
})

-- helper for trace_chain_callbacks
-- ignores return values from successfull calls but logs tracebacks for throws
local function void_xpcall_log_tb(func, req, msg)
	local ok, err = xpcall(func, debug.traceback, req, msg)
	if not ok then
		log_error(ffi.C.LOG_GRP_SYSTEM, 'callback %s req %s msg %s stack traceback:\n%s', func, req, msg, err)
	end
end

local function void_xpcall_finish_tb(func, req)
	local ok, err = xpcall(func, debug.traceback, req)
	if not ok then
		log_error(ffi.C.LOG_GRP_SYSTEM, 'callback %s req %s stack traceback:\n%s', func, req, err)
	end
end


-- Metatype for request
local kr_request_t = ffi.typeof('struct kr_request')
ffi.metatype( kr_request_t, {
	__index = {
		-- makes sense only when request is finished
		all_from_cache = function(req)
			assert(ffi.istype(kr_request_t, req))
			local rplan = ffi.C.kr_resolve_plan(req)
			if tonumber(rplan.pending.len) > 0 then
				-- an unresolved query,
				-- i.e. something is missing from the cache
				return false
			end
			for idx=0, tonumber(rplan.resolved.len) - 1 do
				if not rplan.resolved.at[idx].flags.CACHED then
					return false
				end
			end
			return true
		end,
		current = function(req)
			assert(ffi.istype(kr_request_t, req))
			if req.current_query == nil then return nil end
			return req.current_query
		end,
		-- returns the initial query that started the request
		initial = function(req)
			assert(ffi.istype(kr_request_t, req))
			local rplan = C.kr_resolve_plan(req)
			if rplan.initial == nil then return nil end
			return rplan.initial
		end,
		-- Return last query on the resolution plan
		last = function(req)
			assert(ffi.istype(kr_request_t, req))
			local query = C.kr_rplan_last(C.kr_resolve_plan(req))
			if query == nil then return end
			return query
		end,
		resolved = function(req)
			assert(ffi.istype(kr_request_t, req))
			local qry = C.kr_rplan_resolved(C.kr_resolve_plan(req))
			if qry == nil then return nil end
			return qry
		end,
		-- returns first resolved sub query for a request
		first_resolved = function(req)
			assert(ffi.istype(kr_request_t, req))
			local rplan = C.kr_resolve_plan(req)
			if not rplan or rplan.resolved.len < 1 then return nil end
			return rplan.resolved.at[0]
		end,
		push = function(req, qname, qtype, qclass, flags, parent)
			assert(ffi.istype(kr_request_t, req))
			flags = kres.mk_qflags(flags) -- compatibility
			local rplan = C.kr_resolve_plan(req)
			local qry = C.kr_rplan_push(rplan, parent, qname, qclass, qtype)
			if qry ~= nil and flags ~= nil then
				C.kr_qflags_set(qry.flags, flags)
			end
			return qry
		end,
		pop = function(req, qry)
			assert(ffi.istype(kr_request_t, req))
			return C.kr_rplan_pop(C.kr_resolve_plan(req), qry)
		end,
		selected_tostring = function(req)
			assert(ffi.istype(kr_request_t, req))
			local buf = {}
			if #req.answ_selected ~= 0 then
				table.insert(buf, string.format('[%05d.00][dbg ] selected rrsets from answer sections:\n', req.uid))
				table.insert(buf, tostring(req.answ_selected))
			end
			if #req.auth_selected ~= 0 then
				table.insert(buf, string.format('[%05d.00][dbg ] selected rrsets from authority sections:\n', req.uid))
				table.insert(buf, tostring(req.auth_selected))
			end
			if #req.add_selected ~= 0 then
				table.insert(buf, string.format('[%05d.00][dbg ] selected rrsets from additional sections:\n', req.uid))
				table.insert(buf, tostring(req.add_selected))
			end
			return table.concat(buf, '')
		end,

		-- chain new callbacks after the old ones
		-- creates new wrapper functions as necessary
		-- note: callbacks are FFI cdata pointers so tests must
		--       use explicit "cb == nil", just "if cb" does not work
		--
		trace_chain_callbacks = function (req, new_log, new_finish)
			local log_wrapper
			if req.trace_log == nil then
				req.trace_log = new_log
			else
				local old_log = req.trace_log
				log_wrapper = ffi.cast('trace_log_f',
				function(cbreq, msg)
					jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
					void_xpcall_log_tb(old_log, cbreq, msg)
					void_xpcall_log_tb(new_log, cbreq, msg)
				end)
				req.trace_log = log_wrapper
			end
			local old_finish = req.trace_finish
			if not (log_wrapper ~= nil or old_finish ~= nil) then
				req.trace_finish = new_finish
			else
				local fin_wrapper
				fin_wrapper = ffi.cast('trace_callback_f',
				function(cbreq)
					jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
					if old_finish ~= nil then
						void_xpcall_finish_tb(old_finish, cbreq)
					end
					if new_finish ~= nil then
						void_xpcall_finish_tb(new_finish, cbreq)
					end
					-- beware: finish callbacks can call log callback
					if log_wrapper ~= nil then
						log_wrapper:free()
					end
					fin_wrapper:free()
				end)
				req.trace_finish = fin_wrapper
			end
		end,

		-- Return per-request variable table
		-- The request can store anything in this Lua table and it will be freed
		-- when the request is closed, it doesn't have to worry about contents.
		vars = function (req)
			assert(ffi.istype(kr_request_t, req))
			-- Return variable if it's already stored
			local var = worker.vars[req.vars_ref]
			if var then
				return var
			end
			-- Either take a slot number from freelist
			-- or find a first free slot (expand the table)
			local ref = worker.vars[0]
			if ref then
				worker.vars[0] = worker.vars[ref]
			else
				ref = #worker.vars + 1
			end
			-- Create new variables table
			var = {}
			worker.vars[ref] = var
			-- Save reference in the request
			req.vars_ref = ref
			return var
		end,
		-- Ensure that answer exists and return it; can't fail.
		ensure_answer = function (req)
			assert(ffi.istype(kr_request_t, req))
			return C.kr_request_ensure_answer(req)
		end,
	},
})

-- C array iterator
local function c_array_iter(t, i)
	i = i + 1
	if i >= t.len then return end
	return i, t.at[i][0]
end

-- Metatype for a single ranked record array entry (one RRset)
local function rank_tostring(rank)
	local names = {}
	for name, value in pairs(const_rank) do
		if ffi.C.kr_rank_test(rank, value) then
			table.insert(names, string.lower(name))
		end
	end
	return string.format('0%.2o (%s)', rank, table.concat(names, ' '))
end

local ranked_rr_array_entry_t = ffi.typeof('ranked_rr_array_entry_t')
ffi.metatype(ranked_rr_array_entry_t, {
	__tostring = function(self)
		return string.format('; ranked rrset to_wire %s, rank %s, cached %s, qry_uid %s, revalidations %s\n%s',
		self.to_wire, rank_tostring(self.rank), self.cached, self.qry_uid,
		self.revalidation_cnt, string.format('%s', self.rr))
	end
})

-- Metatype for ranked record array (array of RRsets)
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
	},
	__tostring = function(self)
		local buf = {}
		for _, rrset in ipairs(self) do
			table.insert(buf, tostring(rrset))
		end
		return table.concat(buf, '')
	end
})

-- Cache metatype
local kr_cache_t = ffi.typeof('struct kr_cache')
ffi.metatype( kr_cache_t, {
	__index = {
		insert = function (self, rr, rrsig, rank, timestamp)
			assert(ffi.istype(kr_cache_t, self))
			assert(ffi.istype(knot_rrset_t, rr), 'RR must be a rrset type')
			assert(not rrsig or ffi.istype(knot_rrset_t, rrsig), 'RRSIG must be nil or of the rrset type')
			-- Get current timestamp
			if not timestamp then
				local now = timeval_t()
				C.gettimeofday(now, nil)
				timestamp = tonumber(now.tv_sec)
			end
			-- Insert record into cache
			local ret = C.kr_cache_insert_rr(self, rr, rrsig, tonumber(rank or 0), timestamp)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
		commit = function (self)
			assert(ffi.istype(kr_cache_t, self))
			local ret = C.kr_cache_commit(self)
			if ret ~= 0 then return nil, knot_error_t(ret) end
			return true
		end,
	},
})

-- Pretty-print a single RR (which is a table with .owner .ttl .type .rdata)
-- Extension: append .comment if exists.
local function rr2str(rr, style)
	-- Construct a single-RR temporary set while minimizing copying.
	local ret
	do
		local rrs = knot_rrset_t(rr.owner, rr.type, kres.class.IN, rr.ttl)
		rrs:add_rdata(rr.rdata, #rr.rdata)
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
	lru = function (max_size, value_type)
	  value_type = value_type or ffi.typeof('uint64_t')
	  local ct = ffi.typeof(typed_lru_t, value_type)
	  return ffi.metatype(ct, lru_metatype)(max_size, ffi.alignof(value_type))
	end,

	-- Metatypes.  Beware that any pointer will be cast silently...
	pkt_t = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	request_t = function (udata) return ffi.cast('struct kr_request *', udata) end,
	sockaddr_t = function (udata) return ffi.cast('struct sockaddr *', udata) end,

	-- Global API functions
	-- Convert a lua string to a lower-case wire format (inside GC-ed ffi.string).
	str2dname = function(name)
		if type(name) ~= 'string' then return end
		local dname = ffi.gc(C.knot_dname_from_str(nil, name, 0), C.free)
		if dname == nil then return nil end
		ffi.C.knot_dname_to_lower(dname);
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
	context = function () return ffi.C.the_worker.engine.resolver end,

	knot_pkt_rr = knot_pkt_rr,
}

return kres
