-- Module interface
local ffi = require('ffi')
local knot = ffi.load(libknot_SONAME)

local priming = {}
priming.retry_time = 10 * sec -- retry time when priming fail

-- internal state variables and functions
local internal = {}
internal.nsset = {}  -- set of resolved nameservers
internal.min_ttl = 0 -- minimal TTL of NS records
internal.to_resolve = 0 -- number of pending queries to A or AAAA
internal.prime = {} -- function triggering priming query
internal.event = nil -- stores event id

-- Copy hints from nsset table to resolver engine
-- These addresses replace root hints loaded by default from file.
-- They are stored outside cache and cache flush will not affect them.
local function publish_hints(nsset)
	local roothints = kres.context().root_hints
	-- reset zone cut and clear address list
	ffi.C.kr_zonecut_set(roothints, kres.str2dname("."))
	for dname, addresses in pairs(nsset) do
		for _, rdata_addr in pairs(addresses) do
			ffi.C.kr_zonecut_add(roothints, dname, rdata_addr)
		end
	end
end

-- Count A and AAAA addresses in nsset
local function count_addresses(nsset)
	local count = 0
	for _, addresses in pairs(nsset) do
		count = count + #addresses
	end
	return count
end

-- Callback for response from A or AAAA query for root nameservers
-- address is added to table internal.nsset.
-- When all response is processed internal.nsset is published in resolver engine
-- luacheck: no unused args
local function address_callback(pkt, req)
	pkt = kres.pkt_t(pkt)
	-- req = kres.request_t(req)
	if pkt:rcode() ~= kres.rcode.NOERROR then
		warn("[priming] cannot resolve address '%s', type: %d", kres.dname2str(pkt:qname()), pkt:qtype())
	else
		local section = pkt:rrsets(kres.section.ANSWER)
		for i = 1, #section do
			local rr = section[i]
			if rr.type == kres.type.A or rr.type == kres.type.AAAA then
				for k = 0, rr.rrs.rr_count-1 do
					table.insert(internal.nsset[rr:owner()], rr.rrs:rdata(k))
				end
			end
		end
	end
	internal.to_resolve = internal.to_resolve - 1
	if internal.to_resolve == 0 then
		if count_addresses(internal.nsset) == 0 then
			warn("[priming] cannot resolve any root server address, next priming query in %d seconds", priming.retry_time / sec)
			internal.event = event.after(priming.retry_time, internal.prime)
		else
			publish_hints(internal.nsset)
			if verbose() then
				log("[priming] triggered priming query, next in %d seconds", internal.min_ttl)
			end
			internal.event = event.after(internal.min_ttl * sec, internal.prime)
		end
	end
end

-- Callback for priming query ('.' NS)
-- For every NS record creates two separate queries for A and AAAA.
-- These new queries should be resolved from cache.
-- luacheck: no unused args
local function priming_callback(pkt, req)
	pkt = kres.pkt_t(pkt)
	-- req = kres.request_t(req)
	if pkt:rcode() ~= kres.rcode.NOERROR then
		warn("[priming] cannot resolve '.' NS, next priming query in %d seconds", priming.retry_time / sec)
		internal.event = event.after(priming.retry_time, internal.prime)
		return nil
	end
	local section = pkt:rrsets(kres.section.ANSWER)
	for i = 1, #section do
		local rr = section[i]
		if rr.type == kres.type.NS then
			internal.min_ttl = math.min(internal.min_ttl, rr:ttl())
			internal.to_resolve = internal.to_resolve + 2 * rr.rrs.rr_count
			for k = 0, rr.rrs.rr_count-1 do
				local nsname_text = rr:tostring(k)
				local nsname_wire = rr:rdata(k) -- FIXME: something is wrong
				internal.nsset[nsname_wire] = {}
				resolve(nsname_text, kres.type.A, kres.class.IN, 0, address_callback)
				resolve(nsname_text, kres.type.AAAA, kres.class.IN, 0, address_callback)
			end
		end
	end
end

-- trigger priming query
function internal.prime()
	internal.min_ttl = math.max(1, cache.max_ttl()) -- sanity check for disabled cache
	internal.nsset = {}
	internal.to_resolve = 0
	resolve(".", kres.type.NS, kres.class.IN, 0, priming_callback)
end

function priming.init()
	if internal.event then
		error("Priming module is already loaded.")
	else
		internal.event = event.after(0 , internal.prime)
	end
end

function priming.deinit()
	if internal.event then
		event.cancel(internal.event)
		internal.event = nil
	end
end

return priming
