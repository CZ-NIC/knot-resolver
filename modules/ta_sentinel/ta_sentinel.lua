local M = {}
M.layer = {}

function M.layer.finish(state, req, pkt)
	local kreq = kres.request_t(req)

	if bit.band(state, kres.DONE) == 0 then
		return state end -- not resolved yet, exit

	local qry = kreq:resolved()
	if qry.parent ~= nil then
		return state end -- an internal query, exit

	local kpkt = kres.pkt_t(pkt)
	if not kpkt:ad() then
		return state end -- insecure answer, exit

	if not (kpkt:qtype() == kres.type.A) and not (kpkt:qtype() == kres.type.AAAA) then
		return state end

	if not (kpkt:qclass() == kres.class.IN) then
		return state end

	local qname = kres.dname2str(qry:name()):lower()
	local sentype, hexkeytag = qname:match('^kskroll%-sentinel%-(is)%-ta%-(%x+)%.')
	if not sentype then
		sentype, hexkeytag = qname:match('^kskroll%-sentinel%-(not)%-ta%-(%x+)%.')
	end
	if not sentype or not hexkeytag then
		return state end -- pattern did not match, exit
	-- end of hot path

	local qkeytag = tonumber(hexkeytag, 16)
	if not qkeytag then
		return state end -- not a valid hex string, exit

	if (qkeytag < 0) or (qkeytag > 0xffff) then
		return state end -- invalid keytag?!, exit
	if verbose() then
		log('[ta_sentinel] key tag: ' .. qkeytag .. ', sentinel: ' .. sentype)
	end
	assert (sentype == 'is' or sentype == 'not')

	local found = false
	for keyidx = 1, #trust_anchors.keysets['\0'] do
		local key = trust_anchors.keysets['\0'][keyidx]
		if qkeytag == key.key_tag then
			found = (key.state == "Valid")
			if verbose() then
				log('[ta_sentinel] found keytag ' .. qkeytag .. ', key state ' .. key.state)
			end
		end
	end

	if (found and sentype == 'is')
	   or (not found and sentype == 'not') then
		kpkt:clear_payload()
		kpkt:rcode(2)
		kpkt:ad(false)
	end
	return state -- do not break resolution process
end

return M
