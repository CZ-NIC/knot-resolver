-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface
local ffi = require('ffi')
local kres = require('kres')
local C = ffi.C

assert(trust_anchors, 'ta_update module depends on initialized trust_anchors library')
local key_state = trust_anchors.key_state
assert(key_state)

local ta_update = {}
local tracked_tas = {}  -- zone name (wire) => {event = number}


-- Find key in current keyset
local function ta_find(keyset, rr)
	local rr_tag = C.kr_dnssec_key_tag(rr.type, rr.rdata, #rr.rdata)
	if rr_tag < 0 or rr_tag > 65535 then
		warn(string.format('[ta_update] ignoring invalid or unsupported RR: %s: %s',
			kres.rr2str(rr), ffi.string(C.knot_strerror(rr_tag))))
		return nil
	end
	for i, ta in ipairs(keyset) do
		-- Match key owner and content
		local ta_tag = C.kr_dnssec_key_tag(ta.type, ta.rdata, #ta.rdata)
		if ta_tag < 0 or ta_tag > 65535 then
			warn(string.format('[ta_update] ignoring invalid or unsupported RR: %s: %s',
				kres.rr2str(ta), ffi.string(C.knot_strerror(ta_tag))))
		else
			if ta.owner == rr.owner then
				if ta.type == rr.type then
					if rr.type == kres.type.DNSKEY then
						if C.kr_dnssec_key_match(ta.rdata, #ta.rdata, rr.rdata, #rr.rdata) == 0 then
							return ta
						end
					elseif rr.type == kres.type.DS and ta.rdata == rr.rdata then
						return ta
					end
				-- DNSKEY superseding DS, inexact match
				elseif rr.type == kres.type.DNSKEY and ta.type == kres.type.DS then
					if ta.key_tag == rr_tag then
						keyset[i] = rr -- Replace current DS
						rr.state = ta.state
						rr.key_tag = ta.key_tag
						return rr
					end
				-- DS key matching DNSKEY, inexact match
				elseif rr.type == kres.type.DS and ta.type == kres.type.DNSKEY then
					if rr_tag == ta_tag then
						return ta
					end
				end
			end
		end
	end
	return nil
end

-- Evaluate TA status of a RR according to RFC5011.  The time is in seconds.
local function ta_present(keyset, rr, hold_down_time)
if rr.type == kres.type.DNSKEY and not C.kr_dnssec_key_ksk(rr.rdata) then
	return false -- Ignore
end
-- Attempt to extract key_tag
local key_tag = C.kr_dnssec_key_tag(rr.type, rr.rdata, #rr.rdata)
if key_tag < 0 or key_tag > 65535 then
	warn(string.format('[ta_update] ignoring invalid or unsupported RR: %s: %s',
		kres.rr2str(rr), ffi.string(C.knot_strerror(key_tag))))
	return false
end
-- Find the key in current key set and check its status
local now = os.time()
local key_revoked = (rr.type == kres.type.DNSKEY) and C.kr_dnssec_key_revoked(rr.rdata)
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
			ta.timer = now + hold_down_time
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
	if rr.state ~= key_state.Valid or verbose() then
		log('[ta_update] key: ' .. key_tag .. ' state: '..ta.state)
	end
	return true
elseif not key_revoked then -- First time seen (NewKey)
	rr.key_tag = key_tag
	return false
end
end

-- TA is missing in the new key set.  The time is in seconds.
local function ta_missing(ta, hold_down_time)
	-- Key is removed (KeyRem)
	local keep_ta = true
	local key_tag = C.kr_dnssec_key_tag(ta.type, ta.rdata, #ta.rdata)
	if key_tag < 0 or key_tag > 65535 then
		warn(string.format('[ta_update] ignoring invalid or unsupported RR: %s: %s',
			kres.rr2str(ta), ffi.string(C.knot_strerror(key_tag))))
		key_tag = ''
	end
	if ta.state == key_state.Valid then
		ta.state = key_state.Missing
		ta.timer = os.time() + hold_down_time

	-- Remove key that is missing for too long
	elseif ta.state == key_state.Missing and os.difftime(ta.timer, os.time()) <= 0 then
		ta.state = key_state.Removed
		log('[ta_update] key: '..key_tag..' removed because missing for too long')
		keep_ta = false

	-- Purge pending key
	elseif ta.state == key_state.AddPend then
		log('[ta_update] key: '..key_tag..' purging')
		keep_ta = false
	end
	log('[ta_update] key: '..key_tag..' state: '..ta.state)
	return keep_ta
end

-- Update existing keyset; return true if successful.
local function update(keyset, new_keys)
	if not new_keys then return false end
	if not keyset.managed then
		-- this may happen due to race condition during testing in CI (refesh time < query time)
		return false
	end

	-- Filter TAs to be purged from the keyset (KeyRem), in three steps
	-- 1: copy TAs to be kept to `keepset`
	local hold_down = (keyset.hold_down_time or ta_update.hold_down_time) / 1000
	local keepset = {}
	local keep_removed = keyset.keep_removed or ta_update.keep_removed
	for _, ta in ipairs(keyset) do
		local keep = true
		if not ta_find(new_keys, ta) then
			-- Ad-hoc: RFC 5011 doesn't mention removing a Missing key.
			-- Let's do it after a very long period has elapsed.
			keep = ta_missing(ta, hold_down * 4)
		end
		-- Purge removed keys
		if ta.state == key_state.Removed then
			if keep_removed > 0 then
				keep_removed = keep_removed - 1
			else
				keep = false
			end
		end
		if keep then
			table.insert(keepset, ta)
		end
	end
	-- 2: remove all TAs - other settings etc. will remain in the keyset
	for i, _ in ipairs(keyset) do
		keyset[i] = nil
	end
	-- 3: move TAs to be kept into the keyset (same indices)
	for k, ta in pairs(keepset) do
		keyset[k] = ta
	end

	-- Evaluate new TAs
	for _, rr in ipairs(new_keys) do
		if (rr.type == kres.type.DNSKEY or rr.type == kres.type.DS) and rr.rdata ~= nil then
			ta_present(keyset, rr, hold_down)
		end
	end

	-- Store the keyset
	trust_anchors.keyset_write(keyset)

	-- Start using the new TAs.
	if not trust_anchors.keyset_publish(keyset) then
		-- TODO: try to rebootstrap if for root?
		return false
	elseif verbose() then
		log('[ta_update] refreshed trust anchors for domain ' .. kres.dname2str(keyset.owner) .. ' are:\n'
			.. trust_anchors.summary(keyset.owner))
	end

	return true
end

-- Refresh the DNSKEYs from the packet, and return time to the next check.
local function active_refresh(keyset, pkt)
	local retry = true
	if pkt:rcode() == kres.rcode.NOERROR then
		local records = pkt:section(kres.section.ANSWER)
		local new_keys = {}
		for _, rr in ipairs(records) do
			if rr.type == kres.type.DNSKEY then
				table.insert(new_keys, rr)
			end
		end
		update(keyset, new_keys)
		retry = false
	else
		warn('[ta_update] active refresh failed for ' .. kres.dname2str(keyset.owner)
			.. ' with rcode: ' .. pkt:rcode())
	end
	-- Calculate refresh/retry timer (RFC 5011, 2.3)
	local min_ttl = retry and day or 15 * day
	for _, rr in ipairs(keyset) do -- 10 or 50% of the original TTL
		min_ttl = math.min(min_ttl, (retry and 100 or 500) * rr.ttl)
	end
	return math.max(hour, min_ttl)
end

-- Plan an event for refreshing DNSKEYs and re-scheduling itself
local function refresh_plan(keyset, delay)
	local owner = keyset.owner
	local owner_str = kres.dname2str(keyset.owner)
	if not tracked_tas[owner] then
		tracked_tas[owner] = {}
	end
	local track_cfg = tracked_tas[owner]
	if track_cfg.event then  -- restart timer if necessary
		event.cancel(track_cfg.event)
	end
	track_cfg.event = event.after(delay, function ()
		log('[ta_update] refreshing TA for ' .. owner_str)
		resolve(owner_str, kres.type.DNSKEY, kres.class.IN, 'NO_CACHE',
		function (pkt)
			-- Schedule itself with updated timeout
			local delay_new = active_refresh(keyset, pkt)
			delay_new = keyset.refresh_time or ta_update.refresh_time or delay_new
			log('[ta_update] next refresh for ' .. owner_str .. ' in '
				.. delay_new/hour .. ' hours')
			refresh_plan(keyset, delay_new)
		end)
	end)
end

ta_update = {
	-- [optional] overrides for global defaults of
	-- hold_down_time, refresh_time, keep_removed
	hold_down_time = 30 * day,
	refresh_time = nil,
	keep_removed = 0,
	tracked = tracked_tas, -- debug and visibility, should not be changed by hand
}

-- start tracking (already loaded) TA with given zone name in wire format
-- do first refresh immediatelly
function ta_update.start(zname)
	local keyset = trust_anchors.keysets[zname]
	if not keyset then
		panic('[ta_update] TA must be configured first before tracking it')
	end
	if not keyset.managed then
		panic('[ta_update] TA is configured as unmanaged; remove it and '
			.. 'add it again as managed using trust_anchors.add_file()')
	end
	refresh_plan(keyset, 0)
end

function ta_update.stop(zname)
	if tracked_tas[zname] then
		event.cancel(tracked_tas[zname].event)
		tracked_tas[zname] = nil
		trust_anchors.keysets[zname].managed = false
	end
end

-- stop all timers
function ta_update.deinit()
	for zname, _ in pairs(tracked_tas) do
		ta_update.stop(zname)
	end
end

return ta_update
