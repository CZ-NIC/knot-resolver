-- Module interface
local ffi = require('ffi')
local bit = require('bit')
local mod = {}
local MARK_DNS64 = bit.lshift(1, 31)
local addr_buf = ffi.new('char[16]')
-- Config
function mod.config (confstr)
	if confstr == nil then return end
	mod.proxy = kres.str2ip(confstr)
	if mod.proxy == nil then error('[dns64] "'..confstr..'" is not a valid address') end
end
-- Layers
mod.layer = {
	consume = function (state, req, pkt)
		if state == kres.FAIL then return state end
		pkt = kres.pkt_t(pkt)
		req = kres.request_t(req)
		qry = req:current()
		-- Observe only authoritative answers
		if mod.proxy == nil or not qry:resolved() then
			return state
		end
		-- Synthetic AAAA from marked A responses
		local answer = pkt:section(kres.section.ANSWER)
		if bit.band(qry.flags, MARK_DNS64) ~= 0 then -- Marked request
			for i = 1, #answer do
				local rr = answer[i]
				-- Synthesise AAAA from A
				if rr.type == kres.type.A then
					ffi.copy(addr_buf, mod.proxy, 16)
					ffi.copy(addr_buf + 12, rr.rdata, 4)
					req.answer:put(rr.owner, rr.ttl, rr.class, kres.type.AAAA, ffi.string(addr_buf, 16))
				end
			end
		else -- Observe AAAA NODATA responses
			local is_nodata = (pkt:rcode() == kres.rcode.NOERROR) and (#answer == 0)
			if pkt:qtype() == kres.type.AAAA and is_nodata and pkt:qname() == qry:name() and qry:final() then
				local next = req:push(pkt:qname(), kres.type.A, kres.class.IN, 0, qry)
				next.flags = bit.band(qry.flags, kres.query.DNSSEC_WANT) + kres.query.AWAIT_CUT + MARK_DNS64
			end
		end
		return state
	end
}
return mod
