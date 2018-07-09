-- Module interface
local ffi = require('ffi')
local M = {}
local addr_buf = ffi.new('char[16]')

-- Config
function M.config (confstr)
	if confstr == nil then return end
	M.proxy = kres.str2ip(confstr)
	if M.proxy == nil then error('[dns64] "'..confstr..'" is not a valid address') end
end

-- Layers
M.layer = {
	consume = function (state, req, pkt)
		if state == kres.FAIL then return state end
		pkt = kres.pkt_t(pkt)
		req = kres.request_t(req)
		local qry = req:current()
		-- Observe only authoritative answers
		if M.proxy == nil or not qry.flags.RESOLVED then
			return state
		end
		-- Synthetic AAAA from marked A responses
		local answer = pkt:section(kres.section.ANSWER)
		if qry.flags.DNS64_MARK then -- Marked request
			local section = pkt.sections[section_id]
			for i = 1, section.count do
				local orig = kres.knot_pkt_rr(section, i - 1)
				if orig.type == kres.type.A then
					-- Disable GC, as this object doesn't own either owner or RDATA, it's just a reference
					local rrs = ffi.gc(kres.rrset(nil, kres.type.AAAA, orig.rclass, orig:ttl()), nil)
					rrs._owner = ffi.cast('knot_dname_t *', orig:owner()) -- explicit cast needed here
					for k = 1, orig.rrs.rr_count do
						local rdata = orig:rdata( k - 1 )
						ffi.copy(addr_buf, M.proxy, 16)
						ffi.copy(addr_buf + 12, rdata, 4)
						ffi.C.knot_rrset_add_rdata(rrs, ffi.string(addr_buf, 16), 16, req.pool)
					end
					-- All referred memory is copied within the function,
					-- so it doesn't matter that lua GCs our variables.
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
			if pkt:qtype() == kres.type.AAAA and is_nodata and pkt:qname() == qry:name()
					and (qry.flags.RESOLVED and qry.parent == nil) then
				local extraFlags = kres.mk_qflags({})
				extraFlags.DNSSEC_WANT = qry.flags.DNSSEC_WANT
				extraFlags.AWAIT_CUT = true
				extraFlags.DNS64_MARK = true
				req:push(pkt:qname(), kres.type.A, kres.class.IN, extraFlags, qry)
			end
		end
		return state
	end
}

return M
