-- Module interface
local ffi = require('ffi')
local bit = require('bit')
local mod = {}
local MARK_DNS64 = bit.lshift(1, 31)
-- Config
function mod.config (confstr)
	if confstr == nil then return end
	mod.proxy = kres.str2ip(confstr)
	if mod.proxy == nil then error('[dns64] "'..confstr..'" is not a valid address') end
end
-- Layers
mod.layer = {
	consume = function (state, req, pkt)
		pkt = kres.pkt_t(pkt)
		req = kres.request_t(req)
		qry = req:current()
		-- Observe only authoritative answers
		if mod.proxy == nil or bit.band(qry.flags, kres.query.RESOLVED) == 0 then
			return state
		end
		-- Synthetic AAAA from marked A responses
		local answer = pkt:section(kres.section.ANSWER)
		if bit.band(qry.flags, MARK_DNS64) ~= 0 then -- Marked request
			for i = 1, #answer do
				local rr = answer[i]
				-- Synthesise address
				local rdata = ffi.new('char [16]')
				ffi.copy(rdata, mod.proxy)
				ffi.copy(rdata + 12, rr.rdata, 4)
				rdata = ffi.string(rdata, 16)
				-- Write to answer
				req.answer:put(rr.owner, rr.ttl, rr.class, kres.type.AAAA, rdata)
			end
			return state
		end
		-- Observe AAAA NODATA responses
		local is_nodata = (pkt:rcode() == kres.rcode.NOERROR) and (#answer == 0)
		if pkt:qtype() == kres.type.AAAA and is_nodata and pkt:qname() == qry:name() then
			local next = req:push(pkt:qname(), kres.type.A, kres.class.IN, 0, qry)
			next.flags = bit.band(qry.flags, kres.query.DNSSEC_WANT) + kres.query.AWAIT_CUT + MARK_DNS64
		end
		return state
	end
}
return mod
