-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface
local ffi = require('ffi')

local mod = {}
local event_id = nil

-- Resolve callback
-- Check time validity of RRSIGs in priming query
-- luacheck: no unused args
local function check_time_callback(pkt, req)
	if pkt:rcode() ~= kres.rcode.NOERROR then
		warn("[detect_time_skew] cannot resolve '.' NS")
		return nil
	end
	local seen_rrsigs = 0
	local valid_rrsigs = 0
	local section = pkt:rrsets(kres.section.ANSWER)
	local now = os.time()
	local time_diff = 0
	local inception = 0
	local expiration = 0
	for i = 1, #section do
		local rr = section[i]
		assert(rr.type)
		if rr.type == kres.type.RRSIG then
			for k = 0, rr.rrs.count - 1 do
				seen_rrsigs = seen_rrsigs + 1
				local rdata = rr:rdata_pt(k)
				inception = ffi.C.kr_rrsig_sig_inception(rdata)
				expiration = ffi.C.kr_rrsig_sig_expiration(rdata)
				if now > expiration then
					-- possitive value = in the future
					time_diff = now - expiration
				elseif now < inception then
					-- negative value = in the past
					time_diff = now - inception
				else
					valid_rrsigs = valid_rrsigs + 1
				end
			end
		end
	end
	if seen_rrsigs == 0 then
		if verbose() then
			log("[detect_time_skew] No RRSIGs received! "..
			    "You really should configure DNSSEC trust anchor for the root.")
		end
	elseif valid_rrsigs == 0 then
		warn("[detect_time_skew] Local system time %q seems to be at "..
		     "least %u seconds in the %s. DNSSEC signatures for '.' NS "..
		     "are not valid %s. Please check your system clock!",
		     os.date("%c", now),
		     math.abs(time_diff),
		     time_diff > 0 and "future" or "past",
		     time_diff > 0 and "yet" or "anymore")
	elseif verbose() then
		log("[detect_time_skew] Local system time %q is within "..
		    "RRSIG validity interval <%q,%q>.", os.date("%c", now),
		    os.date("%c", inception), os.date("%c", expiration))
	end
end

-- Make priming query and check time validty of RRSIGs.
local function check_time()
	resolve(".", kres.type.NS, kres.class.IN, {"DNSSEC_WANT", "DNSSEC_CD"},
                check_time_callback)
end

function mod.init()
	if event_id then
		error("Module is already loaded.")
	else
		event_id = event.after(0 , check_time)
	end
end

function mod.deinit()
	if event_id then
		event.cancel(event_id)
		event_id = nil
	end
end

return mod
