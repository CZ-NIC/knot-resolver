-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local ffi_ok, ffi = pcall(require, 'ffi')
if not ffi_ok then
	local M = { error = 'FFI not available, resolver bindings disabled.' }
	setmetatable(M, {__index = function(t,k,v) error(rawget(M, 'error')) end })
	return M
end
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load(libknot_SONAME)

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
struct query_flag {
	static const int NO_MINIMIZE = 1 << 0;
	static const int NO_THROTTLE = 1 << 1;
	static const int NO_IPV6     = 1 << 2;
	static const int NO_IPV4     = 1 << 3;
	static const int RESOLVED    = 1 << 5;
	static const int AWAIT_CUT   = 1 << 8;
	static const int CACHED      = 1 << 10;
	static const int NO_CACHE    = 1 << 11;
	static const int EXPIRING    = 1 << 12;
	static const int DNSSEC_WANT = 1 << 14;
	static const int DNSSEC_BOGUS    = 1 << 15;
	static const int DNSSEC_INSECURE = 1 << 16;
	static const int STUB        = 1 << 17;
	static const int ALWAYS_CUT  = 1 << 18;
	static const int PERMISSIVE  = 1 << 20;
	static const int STRICT      = 1 << 21;
	static const int BADCOOKIE_AGAIN = 1 << 22;
	static const int CNAME       = 1 << 23;
	static const int REORDER_RR  = 1 << 24;
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

/* libknot */
typedef struct {
	uint8_t _stub[]; /* Do not touch */
} knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
typedef int knot_section_t; /* Do not touch */
typedef void knot_rrinfo_t; /* Do not touch */
typedef uint8_t knot_dname_t;
typedef uint8_t knot_rdata_t;
typedef struct knot_rdataset {
	uint16_t count;
	knot_rdata_t *data;
} knot_rdataset_t;
typedef struct knot_rrset {
	knot_dname_t *_owner;
	uint16_t type;
	uint16_t class;
	knot_rdataset_t rr;
} knot_rrset_t;
typedef struct {
	struct knot_pkt *pkt;
	uint16_t pos;
	uint16_t count;
} knot_pktsection_t;
typedef struct {
	uint8_t *wire;
	size_t size;
	size_t max_size;
	size_t parsed;
	uint16_t reserved;
	uint16_t qname_size;
	uint16_t rrset_count;
	uint16_t flags;
	knot_rrset_t *opt;
	knot_rrset_t *tsig;
	knot_section_t _current;
	knot_pktsection_t _sections[3];
	size_t _rrset_allocd;
	knot_rrinfo_t *_rr_info;
	knot_rrset_t *_rr;
	uint8_t _stub[]; /* Do not touch */
} knot_pkt_t;

/* generics */
typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef struct {
	void *root;
	map_alloc_f malloc;
	map_free_f free;
	void *baton;
} map_t;

/* libkres */
typedef struct {
	knot_rrset_t *at;
	size_t len;
	size_t cap;
} rr_array_t;
struct kr_zonecut {
	knot_dname_t *name;
	knot_rrset_t *key;
	knot_rrset_t *trust_anchor;
	uint8_t _stub[]; /* Do not touch */
};
struct kr_query {
	struct kr_query *parent;
	knot_dname_t *sname;
	uint16_t type;
	uint16_t class;
	uint16_t id;
	uint32_t flags;
	uint32_t secret;
	uint16_t fails;
	struct timeval timestamp;
	struct kr_zonecut zone_cut;
	uint8_t _stub[]; /* Do not touch */
};
struct kr_rplan {
	uint8_t _stub[]; /* Do not touch */
};
struct kr_request {
	struct kr_context *ctx;
	knot_pkt_t *answer;
	struct kr_query *current_query;
	struct {
		const knot_rrset_t *key;
		const struct sockaddr *addr;
		const struct sockaddr *dst_addr;
		const knot_pkt_t *packet;
		const knot_rrset_t *opt;
	} qsource;
	struct {
	    unsigned rtt;
	    const struct sockaddr *addr;
	} upstream;
	uint32_t options;
	int state;
	rr_array_t authority;
	rr_array_t additional;
	uint8_t _stub[]; /* Do not touch */
};
struct kr_context
{	
	uint32_t options;
	knot_rrset_t *opt_rr;
	map_t trust_anchors;
	map_t negative_anchors;
	uint8_t _stub[]; /* Do not touch */
};

/*
 * libc APIs
 */
void free(void *ptr);
int inet_pton(int af, const char *src, void *dst);

/*
 * libknot APIs
 */
/* Domain names */
int knot_dname_size(const knot_dname_t *name);
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen);
/* Resource records */
uint16_t knot_rdata_rdlen(const knot_rdata_t *rr);
uint8_t *knot_rdata_data(const knot_rdata_t *rr);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, size_t pos);
uint32_t knot_rrset_ttl(const knot_rrset_t *rrset);
int knot_rrset_txt_dump_data(const knot_rrset_t *rrset, size_t pos, char *dst, size_t maxlen, const knot_dump_style_t *style);
int knot_rrset_txt_dump(const knot_rrset_t *rrset, char *dst, size_t maxlen, const knot_dump_style_t *style);

/* Packet */
const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt);
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt);
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt);
int knot_pkt_begin(knot_pkt_t *pkt, int section_id);
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section, uint16_t i);
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt,
                                          knot_section_t section_id);

/* 
 * libkres API
 */
/* Resolution request */
struct kr_rplan *kr_resolve_plan(struct kr_request *request);
void *kr_resolve_pool(struct kr_request *request);
/* Resolution plan */
struct kr_query *kr_rplan_push(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type);
struct kr_query *kr_rplan_resolved(struct kr_rplan *rplan);
struct kr_query *kr_rplan_next(struct kr_query *qry);
/* Nameservers */
int kr_nsrep_set(struct kr_query *qry, size_t index, uint8_t *addr, size_t addr_len, int port);
/* Query */
/* Utils */
unsigned kr_rand_uint(unsigned max);
int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen);
int kr_pkt_recycle(knot_pkt_t *pkt);
const char *kr_inaddr(const struct sockaddr *addr);
int kr_inaddr_family(const struct sockaddr *addr);
int kr_inaddr_len(const struct sockaddr *addr);
int kr_straddr_family(const char *addr);
int kr_straddr_subnet(void *dst, const char *addr);
int kr_bitcmp(const char *a, const char *b, int bits);
int kr_family_len(int family);
int kr_rrarray_add(rr_array_t *array, const knot_rrset_t *rr, void *pool);
/* Trust anchors */
knot_rrset_t *kr_ta_get(map_t *trust_anchors, const knot_dname_t *name);
int kr_ta_add(map_t *trust_anchors, const knot_dname_t *name, uint16_t type,
               uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);
int kr_ta_del(map_t *trust_anchors, const knot_dname_t *name);
void kr_ta_clear(map_t *trust_anchors);
/* DNSSEC */
bool kr_dnssec_key_ksk(const uint8_t *dnskey_rdata);
bool kr_dnssec_key_revoked(const uint8_t *dnskey_rdata);
int kr_dnssec_key_tag(uint16_t rrtype, const uint8_t *rdata, size_t rdlen);
int kr_dnssec_key_match(const uint8_t *key_a_rdata, size_t key_a_rdlen,
                        const uint8_t *key_b_rdata, size_t key_b_rdlen);
]]

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
			local rdata = knot.knot_rdataset_at(rr.rr, i)
			return ffi.string(knot.knot_rdata_data(rdata), knot.knot_rdata_rdlen(rdata))
		end,
		get = function(rr, i)
			return {owner = rr:owner(),
			        ttl = rr:ttl(),
			        class = tonumber(rr.class),
			        type = tonumber(rr.type),
			        rdata = rr:rdata(i)}
		end,
		tostring = function(rr, i)
			assert(ffi.istype(knot_rrset_t, rr))
			if rr.rr.count > 0 then
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
				for k = 1, rrset.rr.count do
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
				C.kr_nsrep_set(qry, i - 1, ffi.cast(ub_t, ns[1]), #ns[1], ns[2] or 53)
			end
			-- If less than maximum NSs, insert guard to terminate the list
			if #list < 4 then
				C.kr_nsrep_set(qry, #list, nil, 0, 0)
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
	NOOP = 0, YIELD = 0, CONSUME = 1, PRODUCE = 2, DONE = 4, FAIL = 8,
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
