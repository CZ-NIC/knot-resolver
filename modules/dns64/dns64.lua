-- Module interface
local ffi = require('ffi')
local M = {}
local addr_buf = ffi.new('char[16]')

--[[
Missing parts of the RFC:
	> The implementation SHOULD support mapping of separate IPv4 address
	> ranges to separate IPv6 prefixes for AAAA record synthesis.  This
	> allows handling of special use IPv4 addresses [RFC5735].

	Also the exclusion prefixes are not implemented, sec. 5.1.4 (MUST).

	TODO: support different prefix lengths, defaulting to /96 if not specified
	https://tools.ietf.org/html/rfc6052#section-2.2

	PTR queries aren't supported (MUST), sec. 5.3.1.2
]]

-- Config
function M.config (confstr)
	M.proxy = kres.str2ip(confstr or '64:ff9b::')
	if M.proxy == nil then error('[dns64] "'..confstr..'" is not a valid address') end
end

-- Layers
M.layer = { }
function M.layer.consume(state, req, pkt)
	if M.proxy == nil then  -- no configuration
		return state
	end

	local rcode = pkt:rcode()
	if (pkt:qclass() ~= kres.class.IN  -- RFC 6147 section 5.1
		or rcode == kres.rcode.NXDOMAIN  -- RFC 6147 section 5.1.2.
		or (req.answer:cd() and req.answer:dobit()) -- RFC 6147 section 5.5
		-- optimization
		or (pkt:qtype() ~= kres.type.AAAA and pkt:qtype() ~= kres.type.A)) then
		return state
	end

	local qry = req:current()
	print(state, pkt:rcode(), tonumber(req.answ_selected.len), pkt:qname(), pkt:qtype(), qry.flags.RESOLVED)
	if bit.band(state, kres.FAIL) ~= 0 and not qry.flags.RESOLVED then
		-- resolution is not finished yet
		return state
	end
	-- Observe final AAAA NODATA responses to the current SNAME.
	local aaaapresent = false
	-- workaround for auths which break on AAAA query
	if bit.band(state, kres.DONE) and rcode == kres.rcode.NOERROR and req.answ_selected.len > 0 then
		-- NOERROR might be NODATA, look for AAAA in answer
		for idx = 0, tonumber(req.answ_selected.len - 1) do
			print(idx)
			if (req.answ_selected.at[idx].to_wire == true
				and req.answ_selected.at[idx].rr.type == kres.type.AAAA)
			then
				aaaapresent = true
				break
			end
		end
	end
	print('aaaapresent ' .. tostring(aaaapresent))
	if pkt:qtype() == kres.type.AAAA and pkt:qname() == qry:name()
			and not qry.flags.CNAME and qry.parent == nil
			and aaaapresent == false then
		-- Start a *marked* corresponding A sub-query.
		local extraFlags = kres.mk_qflags({})
		extraFlags.DNSSEC_WANT = qry.flags.DNSSEC_WANT
		extraFlags.AWAIT_CUT = true
		extraFlags.DNS64_MARK = true
		req:push(pkt:qname(), kres.type.A, kres.class.IN, extraFlags, qry)
		return state
	end

	-- Synthetic AAAA from marked A responses
	-- Observe answer to the marked sub-query, and convert all A records in ANSWER
	-- to corresponding AAAA records to be put into the request's answer.
	if not qry.flags.DNS64_MARK then return state end
	-- Find rank for the NODATA answer.
	-- That will result into corresponding AD flag.  See RFC 6147 5.5.2.
	local neg_rank
	if qry.parent.flags.DNSSEC_WANT and not qry.parent.flags.DNSSEC_INSECURE
		then neg_rank = ffi.C.KR_RANK_SECURE
		else neg_rank = ffi.C.KR_RANK_INSECURE
	end
	-- Find TTL bound from SOA, according to RFC 6147 5.1.7.4.
	local max_ttl = 600
	for i = 1, tonumber(req.auth_selected.len) do
		local entry = req.auth_selected.at[i - 1]
		if entry.qry_uid == qry.parent.uid and entry.rr
				and entry.rr.type == kres.type.SOA
				and entry.rr.rclass == kres.class.IN then
			max_ttl = entry.rr:ttl()
		end
	end
	-- Find the As and do the conversion itself.
	for i = 1, tonumber(req.answ_selected.len) do
		local orig = req.answ_selected.at[i - 1]
		if orig.qry_uid == qry.uid and orig.rr.type == kres.type.A then
			local rank = neg_rank
			if orig.rank < rank then rank = orig.rank end
			-- Disable GC, as this object doesn't own owner or RDATA, it's just a reference
			local ttl = orig.rr:ttl()
			if ttl > max_ttl then ttl = max_ttl end
			local rrs = ffi.gc(kres.rrset(nil, kres.type.AAAA, orig.rr.rclass, ttl), nil)
			rrs._owner = orig.rr._owner
			for k = 1, orig.rr.rrs.count do
				local rdata = orig.rr:rdata( k - 1 )
				ffi.copy(addr_buf, M.proxy, 12)
				ffi.copy(addr_buf + 12, rdata, 4)
				ffi.C.knot_rrset_add_rdata(rrs, ffi.string(addr_buf, 16), 16, req.pool)
			end
			ffi.C.kr_ranked_rrarray_add(
				req.answ_selected,
				rrs,
				rank,
				true,
				qry.uid,
				req.pool)
		end
	end
end

return M
