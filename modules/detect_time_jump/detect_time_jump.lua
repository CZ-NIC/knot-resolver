-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface
local ffi = require('ffi')

local mod = {}
mod.threshold = 10 * min
local event_id = nil

-- Get time of last cache clear. Compute difference between realtime
-- and monotonic time. Compute difference of actual realtime and monotonic
-- time. In ideal case these differences should be almost same.
-- If they differ more than mod.threshold value then clear cache.
local function check_time()
	local checkpoint = cache.checkpoint()
	local cache_timeshift = checkpoint.walltime.sec * 1000 - checkpoint.monotime
	local actual_timeshift = os.time() * 1000 - tonumber(ffi.C.kr_now())
	local jump_backward = cache_timeshift - actual_timeshift
	if jump_backward > mod.threshold then
		log_info(ffi.C.LOG_GRP_DETECTTIMEJUMP, "Detected backwards time jump, clearing cache.\n" ..
		"But what does that mean? It means your future hasn't been written yet."
		)
		cache.clear()
	elseif -jump_backward > mod.threshold then
		-- On Linux 4.17+ this shouldn't happen anymore: https://lwn.net/Articles/751482/
		log_info(ffi.C.LOG_GRP_DETECTTIMEJUMP, "Detected forward time jump.  (Suspend-resume, possibly.)")
		cache.checkpoint(true)
	end
end

function mod.init()
	if event_id then
		error("Module is already loaded.")
	else
		event_id = event.recurrent(1 * min , check_time)
	end
end

function mod.deinit()
	if event_id then
		event.cancel(event_id)
		event_id = nil
	end
end

return mod
