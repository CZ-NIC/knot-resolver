local kres = require('kres')
local C = require('ffi').C

-- Add or remove hold-down timer
local hold_down_time = 30 * day

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
		   C.kr_dnssec_key_match(ta.rdata, #ta.rdata, rr.rdata, #rr.rdata) then
		   return ta
		end
	end
	return nil
end

-- Evaluate TA status according to RFC5011
local function ta_present(keyset, rr, force)
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
local function ta_missing(keyset, ta)
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

-- TA store management
local trust_anchors = {
	keyset = {},
	insecure = {},
	-- Update existing keyset
	update = function (new_keys, initial)
		if not new_keys then return false end
		-- Filter TAs to be purged from the keyset (KeyRem)
		local keyset_keep = {}
		local keyset = trust_anchors.keyset
		for i = 1, #keyset do
			local ta = keyset[i]
			local keep = true
			if not ta_find(new_keys, ta) then
				keep = ta_missing(keyset, ta)
			end
			if keep then
				table.insert(keyset_keep, rr)
			end
		end
		keyset = keyset_keep
		-- Evaluate new TAs
		for i = 1, #new_keys do
			local rr = new_keys[i]
			if rr.type == kres.type.DNSKEY then
				ta_present(keyset, rr, initial)
			end
		end
		-- Publish active TAs
		local store = kres.context().trust_anchors
		C.kr_ta_clear(store)
		for i = 1, #keyset do
			local ta = keyset[i]
			-- Key MAY be used as a TA only in these two states (RFC5011, 4.2)
			if ta.state == key_state.Valid or ta.state == key_state.Missing then
				C.kr_ta_add(store, ta.owner, ta.type, ta.ttl, ta.rdata, #ta.rdata)
			end
		end
		trust_anchors.keyset = keyset
		return true
	end,
	-- Load keys from a file (managed)
	config = function (path)
		local new_keys = require('zonefile').parse_file(path)
		trust_anchors.update(new_keys, true)
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