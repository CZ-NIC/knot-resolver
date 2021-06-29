-- SPDX-License-Identifier: GPL-3.0-or-later
local M = {}
M.layer = {}
local ffi = require('ffi')

function M.layer.finish(state, req, pkt)
	if pkt == nil then return end
	-- fast filter by the length of the first QNAME label
	if pkt.wire[5] == 0 then return state end -- QDCOUNT % 256 == 0, in case we produced that
	local label_len = pkt.wire[12]
	if label_len ~= 29 and label_len ~= 30 then
		return state end
	-- end of hot path

	local qtype = pkt:qtype()
	if not (qtype == kres.type.A or qtype == kres.type.AAAA) then
		return state end
	if bit.band(state, kres.FAIL) ~= 0 then
		return state end

	-- check the label name
	local qry = req:resolved()
	local qname = kres.dname2str(qry:name()):lower()
	local sentype, keytag
	if label_len == 29 then
		sentype = true
		keytag = qname:match('^root%-key%-sentinel%-is%-ta%-(%x+)%.')
	elseif label_len == 30 then
		sentype = false
		keytag = qname:match('^root%-key%-sentinel%-not%-ta%-(%x+)%.')
	end
	if not keytag then return state end

	if req.rank ~= ffi.C.KR_RANK_SECURE or req.answer:cd() then
		log_info(ffi.C.TASENTINEL, 'name+type OK but not AD+CD conditions')
		return state
	end

	-- check keytag from the label
	keytag = tonumber(keytag)
	if not keytag or math.floor(keytag) ~= keytag then
		return state end -- pattern did not match, exit
	if keytag < 0 or keytag > 0xffff then
		return state end -- invalid keytag?!, exit

	log_info(ffi.C.TASENTINEL, 'key tag: ' .. keytag .. ', sentinel: ' .. tostring(sentype))

	local found = false
	local ds_set = ffi.C.kr_ta_get(kres.context().trust_anchors, '\0')
	if ds_set ~= nil then
		for i = 0, ds_set:rdcount() - 1 do
			-- Find the key tag in rdata and compare
			-- https://tools.ietf.org/html/rfc4034#section-5.1
			local rdata = ds_set:rdata_pt(i)
			local tag = rdata.data[0] * 256 + rdata.data[1]
			if tag == keytag then
				found = true
			end
		end
	end
	log_info(ffi.C.TASENTINEL, 'matching trusted TA found: ' .. tostring(found))
	if not found then -- print matching TAs in *other* states than Valid
		for i = 1, #(trust_anchors.keysets['\0'] or {}) do
			local key = trust_anchors.keysets['\0'][i]
			if key.key_tag == keytag and key.state ~= 'Valid' then
				log_info(ffi.C.TASENTINEL, 'matching UNtrusted TA found in state: '
					.. key.state)
			end
		end
	end

	if sentype ~= found then -- expected key is not there, or unexpected key is there
		pkt:clear_payload()
		pkt:rcode(kres.rcode.SERVFAIL)
		pkt:ad(false)
	end
	return state -- do not break resolution process
end

return M
