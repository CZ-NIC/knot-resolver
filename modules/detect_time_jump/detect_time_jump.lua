-- Module interface
local ffi = require('ffi')

local mod = {}
mod.threshold = 10 * min
local event_id = nil

-- Get time of last cache clear. Compute difference between realtime
-- adn monotonic time. Compute difference of actual realtime and monotonic
-- time. In ideal case these differences should be almost same.
-- If they differ more than mod.threshold value then clear cache.
local function check_time()
	local clear_time = cache.last_clear()
	local cache_timeshift = clear_time.walltime.sec * 1000 - clear_time.monotime
	local actual_timeshift = os.time() * 1000 - tonumber(ffi.C.kr_now())
	local time_diff = math.abs(cache_timeshift - actual_timeshift)
	log("check_time, %d", time_diff)
	if time_diff > mod.threshold then
		log("Detected time change, clearing cache\n" ..
		"But what does that mean? It means your future hasn't been written yet."
		)
		cache.clear()
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
