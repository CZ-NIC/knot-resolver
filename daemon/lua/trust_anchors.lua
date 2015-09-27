local kres = require('kres')
local C = require('ffi').C

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
		   C.kr_dnssec_key_match(ta.rdata, #ta.rdata, rr.rdata, #rr.rdata) == 0 then
		   return ta
		end
	end
	return nil
end

-- Evaluate TA status according to RFC5011
local function ta_present(keyset, rr, hold_down_time, force)
	if not C.kr_dnssec_key_ksk(rr.rdata) then
		return false -- Ignore
	end
	-- Find the key in current key set and check its status
	local now = os.time()
	local key_revoked = C.kr_dnssec_key_revoked(rr.rdata)
	local key_tag = C.kr_dnssec_key_tag(rr.type, rr.rdata, #rr.rdata)
	local ta = ta_find(keyset, rr)
	if ta then
		-- Key reappears (KeyPres)
		if ta.state == key_state.Missing then
			ta.state = key_state.Valid
			ta.timer = nil
		end
		-- Key is revoked (RevBit)
		if ta.state == key_state.Valid or ta.state == key_state.Missing then
			if key_revoked then
				ta.state = key_state.Revoked
				ta.timer = os.time() + hold_down_time
			end
		end
		-- Remove hold-down timer expires (RemTime)
		if ta.state == key_state.Revoked and os.difftime(ta.timer, now) <= 0 then
			ta.state = key_state.Removed
			ta.timer = nil
		end
		-- Add hold-down timer expires (AddTime)
		if ta.state == key_state.AddPend and os.difftime(ta.timer, now) <= 0 then
			ta.state = key_state.Valid
			ta.timer = nil
		end
		print('[trust_anchors] key: '..key_tag..' state: '..ta.state)
		return true
	elseif not key_revoked then -- First time seen (NewKey)
		rr.key_tag = key_tag
		if force then
			rr.state = key_state.Valid
		else
			rr.state = key_state.AddPend
			rr.timer = now + hold_down_time
		end
		print('[trust_anchors] key: '..key_tag..' state: '..rr.state)
		table.insert(keyset, rr)
		return true
	end
	return false
end

-- TA is missing in the new key set
local function ta_missing(keyset, ta, hold_down_time)
	-- Key is removed (KeyRem)
	local keep_ta = true
	local key_tag = C.kr_dnssec_key_tag(ta.type, ta.rdata, #ta.rdata)
	if ta.state == key_state.Valid then
		ta.state = key_state.Missing
		ta.timer = os.time() + hold_down_time
	-- Purge pending key
	elseif ta.state == key_state.AddPend then
		print('[trust_anchors] key: '..key_tag..' purging')
		keep_ta = false
	end
	print('[trust_anchors] key: '..key_tag..' state: '..ta.state)
	return keep_ta
end

-- Plan refresh event and re-schedule itself based on the result of the callback
local function refresh_plan(trust_anchors, timeout, refresh_cb)
	if trust_anchors.refresh_ev ~= nil then event.cancel(trust_anchors.refresh_ev) end
	trust_anchors.refresh_ev = event.after(timeout, function (ev)
		worker.resolve('.', kres.type.DNSKEY, kres.class.IN, kres.query.NO_CACHE,
		function (pkt)
			-- Schedule itself with updated timeout
			local next_time = refresh_cb(trust_anchors, kres.pkt_t(pkt))
			next_time = math.min(next_time, trust_anchors.refresh_time)
			print('[trust_anchors] next refresh: '..next_time)
			refresh_plan(trust_anchors, next_time, refresh_cb)
		end)
	end)
end

-- Active refresh, return time of the next check
local function active_refresh(trust_anchors, pkt)
	local retry = true
	if pkt:rcode() == kres.rcode.NOERROR then
		local records = pkt:section(kres.section.ANSWER)
		local keyset = {}
		for i = 1, #records do
			local rr = records[i]
			if rr.type == kres.type.DNSKEY then
				table.insert(keyset, rr)
			end
		end
		trust_anchors.update(keyset, false)
		retry = false
	end
	-- Calculate refresh/retry timer (RFC 5011, 2.3)
	local min_ttl = retry and day or 15 * day
	for i, rr in ipairs(trust_anchors.keyset) do -- 10 or 50% of the original TTL
		min_ttl = math.min(min_ttl, (retry and 100 or 500) * rr.ttl)
	end
	return math.max(hour, min_ttl)
end

-- Write keyset to a file
local function keyset_write(keyset, path)
	local file = assert(io.open(path..'.lock', 'w'))
	for i = 1, #keyset do
		local ta = keyset[i]
		local rr_str = string.format('%s ; %s\n', kres.rr2str(ta), ta.state)
		if ta.state ~= key_state.Valid and ta.state ~= key_state.Missing then
			rr_str = '; '..rr_str -- Invalidate key string
		end
		file:write(rr_str)
	end
	file:close()
	os.rename(path..'.lock', path)
end

-- TA store management
local trust_anchors = {
	keyset = {},
	insecure = {},
	hold_down_time = 30 * day,
	-- Update existing keyset
	update = function (new_keys, initial)
		if not new_keys then return false end
		-- Filter TAs to be purged from the keyset (KeyRem)
		local hold_down = trust_anchors.hold_down_time / 1000
		local keyset_keep = {}
		local keyset = trust_anchors.keyset
		for i = 1, #keyset do
			local ta = keyset[i]
			local keep = true
			if not ta_find(new_keys, ta) then
				keep = ta_missing(trust_anchors, keyset, ta, hold_down)
			end
			if keep then
				table.insert(keyset_keep, ta)
			end
		end
		keyset = keyset_keep
		-- Evaluate new TAs
		for i = 1, #new_keys do
			local rr = new_keys[i]
			if rr.type == kres.type.DNSKEY then
				ta_present(keyset, rr, hold_down, initial)
			end
		end
		-- Publish active TAs
		local store = kres.context().trust_anchors
		C.kr_ta_clear(store)
		if #keyset == 0 then return false end
		for i = 1, #keyset do
			local ta = keyset[i]
			-- Key MAY be used as a TA only in these two states (RFC5011, 4.2)
			if ta.state == key_state.Valid or ta.state == key_state.Missing then
				C.kr_ta_add(store, ta.owner, ta.type, ta.ttl, ta.rdata, #ta.rdata)
			end
		end
		trust_anchors.keyset = keyset
		-- Store keyset in the file
		if trust_anchors.file_current ~= nil then
			keyset_write(keyset, trust_anchors.file_current)
		end
		return true
	end,
	-- Load keys from a file (managed)
	config = function (path, is_unmanaged)
		local new_keys = require('zonefile').parse_file(path)
		trust_anchors.file_current = path
		if is_unmanaged then trust_anchors.file_current = nil end
		trust_anchors.keyset = {}
		if trust_anchors.update(new_keys, true) then
			refresh_plan(trust_anchors, sec, active_refresh)
		end
	end,
	-- Add DS/DNSKEY record(s) (unmanaged)
	add = function (keystr)
		local store = kres.context().trust_anchors
		require('zonefile').parser(function (p)
			local rr = p:current_rr()
			C.kr_ta_add(store, rr.owner, rr.type, rr.ttl, rr.rdata, #rr.rdata)
		end):read(keystr..'\n')
	end,
	-- Negative TA management
	set_insecure = function (list)
		local store = kres.context().negative_anchors
		C.kr_ta_clear(store)
		for i = 1, #list do
			local dname = kres.str2dname(list[i])
			C.kr_ta_add(store, dname, kres.type.DS, 0, nil, 0)
		end
		trust_anchors.insecure = list
	end,
}

return trust_anchors