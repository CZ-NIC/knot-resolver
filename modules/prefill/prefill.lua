local https = require('ssl.https')
local ltn12 = require('ltn12')
local lfs = require('lfs')

local rz_url = "https://www.internic.net/domain/root.zone"
local rz_local_fname = "root.zone"
local rz_ca_dir = nil
local rz_event_id = nil

local rz_default_interval = 86400
local rz_https_fail_interval = 600
local rz_no_ta_interval = 600
local rz_initial_interval = 15
local rz_cur_interval = rz_default_interval
local rz_interval_randomizator_limit = 10
local rz_next_refresh = 86400
local rz_interval_threshold = 5
local rz_interval_min = 3600

local prefill = {
}


-- Fetch over HTTPS with peert cert checked
local function https_fetch(url, ca_dir)
	assert(string.match(url, '^https://'))
	assert(ca_dir)

	local resp = {}
	local r, c = https.request{
	       url = url,
	       verify = {'peer', 'fail_if_no_peer_cert' },
	       capath = ca_dir,
	       protocol = 'tlsv1_2',
	       sink = ltn12.sink.table(resp),
	}
	if r == nil then
		return r, c
	end
	return resp, "[prefill] "..url.." downloaded"
end

-- Write root zone to a file.
local function rzone_write(rzone)
	local file = assert(io.open(rz_local_fname, 'w'))
	for i = 1, #rzone do
		local rzone_chunk = rzone[i]
		file:write(rzone_chunk)
	end
	file:close()
end

local function display_delay(time)
	local days = math.floor(time / 86400)
	local hours = math.floor((time % 86400) / 3600)
	local minutes = math.floor((time % 3600) / 60)
	local seconds = math.floor(time % 60)
	if days > 0 then
		return string.format("%d days %02d hours", days, hours)
	elseif hours > 0 then
		return string.format("%02d hours %02d minutes", hours, minutes)
	elseif minutes > 0 then
		return string.format("%02d minutes %02d seconds", minutes, seconds)
	end
	return string.format("%02d seconds", seconds)
end

local function check_time()
	local expected_refresh = rz_next_refresh
	local attrs = lfs.attributes(rz_local_fname)
	if attrs then
		expected_refresh = attrs.modification + rz_cur_interval
	end

	local delay = expected_refresh - os.time()
	if (delay > rz_interval_threshold) then
		log("[prefill] next refresh for . in %s" , display_delay(delay))
		event.reschedule(rz_event_id, delay * sec)
		return
	end

	log("[prefill] downloading root zone...")
	local rzone, err = https_fetch(rz_url, rz_ca_dir)
	if rzone == nil then
		log(string.format("[prefill] fetch of `%s` failed: %s", rz_url, err))
		rz_cur_interval = rz_https_fail_interval;
		rz_next_refresh = os.time() + rz_cur_interval
		event.reschedule(rz_event_id, rz_cur_interval * sec)
		log("[prefill] next refresh for . in %s", display_delay(rz_cur_interval))
		return
	end

	log("[prefill] saving root zone...")
	rzone_write(rzone)
	local res  = cache.zone_import('root.zone')
	if res.code == 1 then -- no TA found, wait
		log("[prefill] no TA found for root zone")
		rz_cur_interval = rz_no_ta_interval
	elseif res.code == 0 then
		log("[prefill] root zone successfully parsed, import started")
		rz_cur_interval = rz_default_interval
	else
		log("[prefill] root zone import failed (%s)", res.msg)
		rz_cur_interval = rz_default_interval
	end

	rz_cur_interval = rz_cur_interval + math.random(rz_interval_randomizator_limit)
	rz_next_refresh = os.time() + rz_cur_interval
	event.reschedule(rz_event_id, rz_cur_interval * sec)
	log("[prefill] next refresh for . in %s", display_delay(rz_cur_interval))
	return
end

function prefill.init()
	math.randomseed(os.time())
end

function prefill.deinit()
	if rz_event_id then
		event.cancel(rz_event_id)
		rz_event_id = nil
	end
end

function prefill.config(config)
	if not config or type(config) ~= 'table' then
		error('[prefill] configuration must be in table')
	end
	if config.interval then
		config.interval = tonumber(config.interval)
		if config.interval < rz_interval_min then
			error('[prefill] refresh interval %d s is too short, '
				.. 'minimal interval is %d s',
				config.interval, rz_interval_min)
		end
		rz_default_interval = config.interval
		rz_cur_interval = config.interval
	end

	if not config.ca_dir then
		error('[prefill] option ca_dir must point '
			.. 'to a directory with CA certificates in PEM format')
	else
		local _, dir_obj = lfs.dir(config.ca_dir)
		dir_obj:close()
	end
	rz_ca_dir = config.ca_dir
	log('[prefill] first download in %i s; refresh interval %s (randomized)',
		rz_initial_interval, display_delay(rz_default_interval))

	-- ability to change intervals
	prefill.deinit()
	rz_event_id = event.after(rz_initial_interval * sec , check_time)
end

return prefill
