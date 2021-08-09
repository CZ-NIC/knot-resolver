-- SPDX-License-Identifier: GPL-3.0-or-later
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
]]

-- Config
function M.config(conf)
	if type(conf) ~= 'table' then
		conf = { prefix = conf }
	end
	M.proxy = kres.str2ip(tostring(conf.prefix or '64:ff9b::'))
	if M.proxy == nil or #M.proxy ~= 16 then
		error(string.format('[dns64] %q is not a valid IPv6 address', conf.prefix), 2)
	end

	M.rev_ttl = conf.rev_ttl or 60
	M.rev_suffix = kres.str2dname(M.proxy
		:sub(1, 96/8)
		-- hexdump, reverse, intersperse by dots
		:gsub('.', function (ch) return string.format('%02x', string.byte(ch)) end)
		:reverse()
		:gsub('.', '%1.')
		.. 'ip6.arpa.'
	)
end

-- Layers
M.layer = { }
function M.layer.consume(state, req, pkt)
	if state == kres.FAIL then return state end
	local qry = req:current()
	-- Observe only final answers in IN class where request has no CD flag.
	if M.proxy == nil or not qry.flags.RESOLVED
			or pkt:qclass() ~= kres.class.IN or req.qsource.packet:cd() then
		return state
	end
	-- Synthetic AAAA from marked A responses
	local answer = pkt:section(kres.section.ANSWER)

	-- Observe final AAAA NODATA responses to the current SNAME.
	local is_nodata = pkt:rcode() == kres.rcode.NOERROR and #answer == 0
	if pkt:qtype() == kres.type.AAAA and is_nodata and pkt:qname() == qry:name()
			and qry.flags.RESOLVED and not qry.flags.CNAME and qry.parent == nil then
		-- Start a *marked* corresponding A sub-query.
		local extraFlags = kres.mk_qflags({})
		extraFlags.DNSSEC_WANT = qry.flags.DNSSEC_WANT
		extraFlags.AWAIT_CUT = true
		extraFlags.DNS64_MARK = true
		req:push(pkt:qname(), kres.type.A, kres.class.IN, extraFlags, qry)
		return state
	end


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
	ffi.C.kr_ranked_rrarray_finalize(req.answ_selected, qry.uid, req.pool);
end

local function hexchar2int(char)
	if char >= string.byte('0') and char <= string.byte('9') then
		return char - string.byte('0')
	elseif char >= string.byte('a') and char <= string.byte('f') then
		return 10 + char - string.byte('a')
	else
		return nil
	end
end

-- Map the reverse subtree by generating CNAMEs; similarly to the hints module.
--
-- RFC 6147.5.3.1.2 says we SHOULD only generate CNAME if it points to data,
-- but I can't see what's wrong with a CNAME to an NXDOMAIN/NODATA
-- Reimplementation idea: as-if we had a DNAME in policy/cache?
function M.layer.produce(state, req, pkt)
	local qry = req.current_query
	local sname = qry.sname
	if ffi.C.knot_dname_in_bailiwick(sname, M.rev_suffix) < 0
		then return end
	-- Update packet question if it was minimized.
	qry.flags.NO_MINIMIZE = true
	if not ffi.C.knot_dname_is_equal(pkt.wire + 12, sname) then
		if not pkt:recycle() or not pkt:question(sname, qry.sclass, qry.stype)
			then return end
	end

	-- Generate a CNAME iff the full address is queried; otherwise leave NODATA.
	local labels_missing = 16*2 + 2 - ffi.C.knot_dname_labels(sname, nil)
	if labels_missing == 0 then
		-- Transforming v6 labels (hex) to v4 ones (decimal) isn't trivial:
		local l = sname
		local v4name = ''
		for _ = 1, 4 do -- append one IPv4 label at a time into v4name
			local v4lab = 0
			for i = 0, 1 do
				if l[0] ~= 1 then return end
				local ch = hexchar2int(l[1])
				if not ch then return end
				v4lab = v4lab + ch * 16^i
				l = l + 2
			end
			v4lab = tostring(v4lab)
			v4name = v4name .. string.char(#v4lab) .. v4lab
		end
		v4name = v4name .. '\7in-addr\4arpa\0'
		if not pkt:put(sname, M.rev_ttl, kres.class.IN, kres.type.CNAME, v4name)
			then return end
	end

	-- Simple finishing touches.
	if labels_missing < 0 then -- and use NXDOMAIN for too long queries
		pkt:rcode(kres.rcode.NXDOMAIN)
	else
		pkt:rcode(kres.rcode.NOERROR)
	end
	pkt.parsed = pkt.size;
	pkt:aa(true)
	pkt:qr(true)
	qry.flags.CACHED = true
end

return M
