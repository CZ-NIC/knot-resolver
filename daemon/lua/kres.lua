-- LuaJIT ffi bindings for libkres, a DNS resolver library.
-- @note Since it's statically compiled, it expects to find the symbols in the C namespace.

local ffi = require('ffi')
local bit = require('bit')
local bor = bit.bor
local band = bit.band
local C = ffi.C
local knot = ffi.load('knot')
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
struct sockaddr {
    uint16_t sa_family;
    uint8_t _stub[]; /* Do not touch */
};

/* libknot */
typedef struct node {
  struct node *next, *prev;
} node_t;
typedef uint8_t knot_dname_t;
typedef struct knot_rdataset {
	uint16_t count;
	uint8_t *data;
} knot_rdataset_t;
typedef struct knot_rrset {
	knot_dname_t *_owner;
	uint16_t type;
	uint16_t class;
	knot_rdataset_t rr;
} knot_rrset_t;
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
	uint16_t flags;
	unsigned secret;
	uint8_t _stub[]; /* Do not touch */
};
struct kr_rplan {
	uint8_t _stub[]; /* Do not touch */
};
struct kr_request {
	struct kr_context *ctx;
	knot_pkt_t *answer;
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
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen);
/* Resource records */
/* Packet */
const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt);
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt);
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt);
int knot_pkt_begin(knot_pkt_t *pkt, int section_id);
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);

/* 
 * libkres API
 */
/* Resolution request */
struct kr_rplan *kr_resolve_plan(struct kr_request *request);
/* Resolution plan */
struct kr_query *kr_rplan_current(struct kr_rplan *rplan);
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
		owner = function(rr) return ffi.string(rr._owner) end,
	}
})

-- Metatype for packet
local knot_pkt_t = ffi.typeof('knot_pkt_t')
ffi.metatype( knot_pkt_t, {
	__index = {
		qname = function(pkt) return ffi.string(knot.knot_pkt_qname(pkt)) end,
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
		name = function(qry) return ffi.string(qry.sname) end,
	},
})
-- Metatype for request
local kr_request_t = ffi.typeof('struct kr_request')
ffi.metatype( kr_request_t, {
	__index = {
		current = function(req)
			assert(req)
			return C.kr_rplan_current(C.kr_resolve_plan(req))
		end,
	},
})

-- Module API
local kres_context = ffi.cast('struct kr_context *', __engine)
local kres = {
	-- Constants
	class = ffi.new('struct rr_class'),
	type = ffi.new('struct rr_type'),
	section = ffi.new('struct pkt_section'),
	rcode = ffi.new('struct pkt_rcode'),
	NOOP = 0, CONSUME = 1, PRODUCE = 2, DONE = 4, FAIL = 8,
	-- Metatypes
	pkt_t = function (udata) return ffi.cast('knot_pkt_t *', udata) end,
	request_t = function (udata) return ffi.cast('struct kr_request *', udata) end,
	-- Global API functions
	str2dname = function(name) return ffi.string(ffi.gc(C.knot_dname_from_str(nil, name, 0), C.free)) end,
	dname2str = function(dname) return ffi.string(ffi.gc(C.knot_dname_to_str(nil, dname, 0), C.free)) end,
	context = function () return kres_context end,
}

-- RFC5011 state table
local key_state = {
	Start = 'Start', AddPend = 'AddPend', Valid = 'Valid',
	Missing = 'Missing', Revoked = 'Revoked', Removed = 'Removed'
}

-- Find key in current keyset
local function ta_find(keyset, rr)
	for i = 1, #keyset do
		local ta = keyset[i]
		-- Match key owner and content
		if ta.owner == rr.owner and
		   C.kr_dnssec_key_match(ta.rdata, #ta.rdata, rr.rdata, #rr.rdata) then
		   return ta
		end
	end
	return nil
end

-- Evaluate TA status according to RFC5011
local function ta_present(keyset, rr, force)
	if not C.kr_dnssec_key_ksk(rr.rdata) then
		return false -- Ignore
	end	
	-- Find the key in current key set and check its status
	local key_revoked = C.kr_dnssec_key_revoked(rr.rdata)
	local key_tag = C.kr_dnssec_key_tag(rr.type, rr.rdata, #rr.rdata)
	local ta = ta_find(keyset, rr)
	if ta then
		-- Key reappears (KeyPres)
		if ta.state == key_state.Missing then ta.state = key_state.Valid end
		-- Key is revoked (RevBit)
		if ta.state == key_state.Valid or ta.state == key_state.Missing then
			if key_revoked then
				ta.state = key_state.Revoked
				-- @todo: ta.time = ...
			end
		end
		-- @todo RemTime
		-- @todo AddTime
		-- Preserve key (KeyPres)
		print('[trust_anchors] key: '..key_tag..' state: '..ta.state)
		return true
	elseif not key_revoked then -- First time seen (NewKey)
		rr.state = force and key_state.Valid or key_state.AddPend
		-- rr.time = ...
		print('[trust_anchors] key: '..key_tag..' state: '..rr.state)
		table.insert(keyset, rr)
		return true
	end
	return false
end

-- TA is missing in the new key set
local function ta_missing(keyset, ta)
	-- Key is removed (KeyRem)
	if ta.state == key_state.Valid then
		ta.state = key_state.Missing
		-- ta.time = ...
	elseif ta.state == key_state.AddPend then
		-- @todo: remove from the set (Start)
	end
	local key_tag = C.kr_dnssec_key_tag(ta.type, ta.rdata, #ta.rdata)
	print('[trust_anchors] key: '..key_tag..' state: '..ta.state)
end

-- TA store management
kres.trust_anchors = {
	keyset = {},
	insecure = {},
	-- Update existing keyset
	update = function (new_keys, initial)
		-- Flag keys missing in new set (KeyRem)
		local keyset = kres.trust_anchors.keyset
		for i = 1, #keyset do
			local ta = keyset[i]
			if not ta_find(new_keys, ta) then
				ta_missing(keyset, ta)
			end
		end
		-- Evaluate new TAs
		if not new_keys then return false end
		for i = 1, #new_keys do
			local rr = new_keys[i]
			if rr.type == kres.type.DNSKEY then
				ta_present(keyset, rr, initial)
			end
		end
		-- Publish active TAs
		local store = kres_context.trust_anchors
		C.kr_ta_clear(store)
		for i = 1, #keyset do
			local ta = keyset[i]
			-- Key MAY be used as a TA only in these two states (RFC5011, 4.2)
			if ta.state == key_state.Valid or ta.state == key_state.Missing then
				C.kr_ta_add(store, ta.owner, ta.type, ta.ttl, ta.rdata, #ta.rdata)
			end
		end
		return true
	end,
	-- Load keys from a file (managed)
	config = function (path)
		local new_keys = require('zonefile').parse_file(path)
		return kres.trust_anchors.update(new_keys, true)
	end,
	-- Add DS/DNSKEY record(s) (unmanaged)
	add = function (keystr)
		local store = kres_context.trust_anchors
		require('zonefile').parser(function (p)
			local rr = p:current_rr()
			C.kr_ta_add(store, rr.owner, rr.type, rr.ttl, rr.rdata, #rr.rdata)
		end):read(keystr..'\n')
	end,
	-- Negative TA management
	set_insecure = function (list)
		C.kr_ta_clear(kres_context.negative_anchors)
		for i = 1, #list do
			local dname = kres.str2dname(list[i])
			C.kr_ta_add(kres_context.negative_anchors, dname, kres.type.DS, 0, nil, 0)
		end
		kres.trust_anchors.insecure = list
	end,
}

return kres