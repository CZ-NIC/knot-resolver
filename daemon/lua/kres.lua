-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local ffi = require('ffi')
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load(libpath('libknot', '1'))
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
	static const int NO_IPV6     = 1 << 2;
	static const int NO_IPV4     = 1 << 3;
	static const int RESOLVED    = 1 << 5;
	static const int AWAIT_CUT   = 1 << 8;
	static const int CACHED      = 1 << 10;
	static const int NO_CACHE    = 1 << 11;
	static const int EXPIRING    = 1 << 12;
	static const int DNSSEC_WANT = 1 << 14;
};

/*
 * Data structures
 */

/* stdlib */
struct sockaddr {
    uint16_t sa_family;
    uint8_t _stub[]; /* Do not touch */
};

/* libknot */
typedef int knot_section_t; /* Do not touch */
typedef void knot_rrinfo_t; /* Do not touch */
typedef struct node {
  struct node *next, *prev;
} node_t;
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
struct kr_query {
	node_t _node;
	struct kr_query *parent;
	knot_dname_t *sname;
	uint16_t type;
	uint16_t class;
	uint16_t id;
	uint32_t flags;
	unsigned secret;
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
	} qsource;
	uint32_t options;
	int state;
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
/* Resolution plan */
struct kr_query *kr_rplan_push(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type);
struct kr_query *kr_rplan_resolved(struct kr_rplan *rplan);
struct kr_query *kr_rplan_next(struct kr_query *qry);
/* Query */
/* Utils */
unsigned kr_rand_uint(unsigned max);
int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen);
const char *kr_inaddr(const struct sockaddr *addr);
int kr_inaddr_len(const struct sockaddr *addr);
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

-- Metatype for sockaddr
local sockaddr_t = ffi.typeof('struct sockaddr')
ffi.metatype( sockaddr_t, {
	__index = {
		len = function(sa) return C.kr_inaddr_len(sa) end,
		ip = function (sa) return C.kr_inaddr(sa) end,
	}
})

-- Metatype for RR set
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
		section = function (pkt, section_id)
			local records = {}
			local section = C.knot_pkt_section(pkt, section_id)
			for i = 0, section.count - 1 do
				local rrset = knot.knot_pkt_rr(section, i)
				for k = 0, rrset.rr.count - 1 do
					table.insert(records, rrset:get(k))
				end
			end
			return records
		end, 
		begin = function (pkt, section) return knot.knot_pkt_begin(pkt, section) end,
		put = function (pkt, owner, ttl, rclass, rtype, rdata)
			return C.kr_pkt_put(pkt, owner, ttl, rclass, rtype, rdata, string.len(rdata))
		end
	},
})
-- Metatype for query
local kr_query_t = ffi.typeof('struct kr_query')
ffi.metatype( kr_query_t, {
	__index = {
		name = function(qry, new_name) return ffi.string(qry.sname) end,
		next = function(qry)
			assert(qry)
			return C.kr_rplan_next(qry)
		end,
	},
})
-- Metatype for request
local kr_request_t = ffi.typeof('struct kr_request')
ffi.metatype( kr_request_t, {
	__index = {
		current = function(req)
			assert(req)
			return req.current_query
		end,
		resolved = function(req)
			assert(req)
			return C.kr_rplan_resolved(C.kr_resolve_plan(req))
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
	query = ffi.new('struct query_flag'),
	NOOP = 0, YIELD = 0, CONSUME = 1, PRODUCE = 2, DONE = 4, FAIL = 8,
	-- Metatypes
	pkt_t = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	request_t = function (udata) return ffi.cast('struct kr_request *', udata) end,
	-- Global API functions
	str2dname = function(name) return ffi.string(ffi.gc(C.knot_dname_from_str(nil, name, 0), C.free)) end,
	dname2str = dname2str,
	rr2str = rr2str,
	context = function () return ffi.cast('struct kr_context *', __engine) end,
}

return kres