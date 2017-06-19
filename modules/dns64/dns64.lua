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
			local section = ffi.C.knot_pkt_section(pkt, kres.section.ANSWER)
			for i = 1, section.count do
				local orig = ffi.C.knot_pkt_rr(section, i - 1)
				if orig.type == kres.type.A then
					local rrs = ffi.typeof('knot_rrset_t')()
					ffi.C.knot_rrset_init_empty(rrs)
					rrs._owner = ffi.cast('char *', orig:owner()) -- explicit cast needed here
					rrs.type = kres.type.AAAA
					rrs.rclass = orig.rclass
					for k = 1, orig.rrs.rr_count do
						local rdata = orig:rdata( k - 1 )
						ffi.copy(addr_buf, mod.proxy, 16)
						ffi.copy(addr_buf + 12, rdata, 4)
						ffi.C.knot_rrset_add_rdata(rrs, ffi.string(addr_buf, 16), 16, orig:ttl(), req.pool)
					end
					ffi.C.kr_ranked_rrarray_add(
						req.answ_selected,
						rrs,
						ffi.C.KR_RANK_OMIT,
						true,
						qry.uid,
						req.pool)
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
