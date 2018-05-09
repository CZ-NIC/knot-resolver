local https = require('ssl.https')
local ltn12 = require('ltn12')
local lfs = require('lfs')

local rz_url = "https://www.internic.net/domain/root.zone"
local rz_local_fname = "root.zone"
local rz_ca_file = nil
local rz_event_id = nil

local rz_default_interval = 86400
local rz_https_fail_interval = 600
local rz_no_ta_interval = 600
local rz_cur_interval = rz_default_interval
local rz_interval_randomizator_limit = 10
local rz_interval_threshold = 5
local rz_interval_min = 3600

local prefill = {
}


-- Fetch over HTTPS with peert cert checked
local function https_fetch(url, ca_file)
	assert(string.match(url, '^https://'))
	assert(ca_file)

	local resp = {}
	local r, c = https.request{
	       url = url,
	       verify = {'peer', 'fail_if_no_peer_cert' },
	       cafile = ca_file,
	       protocol = 'tlsv1_2',
	       sink = ltn12.sink.table(resp),
	}
	if r == nil then
		return r, c
	end
	return resp, "[prefill] "..url.." downloaded"
end

-- Write zone to a file
local function zone_write(zone, fname)
	local file, errmsg = io.open(fname, 'w')
	if not file then
		error(string.format("[prefill] unable to open file %s (%s)",
			fname, errmsg))
	end
	for i = 1, #zone do
		local zone_chunk = zone[i]
		file:write(zone_chunk)
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

-- returns: number of seconds the file is valid for
-- 0 indicates immediate download
local function get_file_ttl(fname)
	local attrs = lfs.attributes(fname)
	if attrs then
		local age = os.time() - attrs.modification
		return math.max(
			rz_cur_interval - age,
			0)
	else
		return 0  -- file does not exist, download now
	end
end

local function download(url, fname)
	log("[prefill] downloading root zone...")
	local rzone, err = https_fetch(url, rz_ca_file)
	if rzone == nil then
		error(string.format("[prefill] fetch of `%s` failed: %s", url, err))
	end

	log("[prefill] saving root zone...")
	zone_write(rzone, fname)
end

local function import(fname)
	local res = cache.zone_import(fname)
	if res.code == 1 then -- no TA found, wait
		error("[prefill] no trust anchor found for root zone, import aborted")
	elseif res.code == 0 then
		log("[prefill] root zone successfully parsed, import started")
	else
		error(string.format("[prefill] root zone import failed (%s)", res.msg))
	end
end

local function timer()
	local file_ttl = get_file_ttl(rz_local_fname)

	if file_ttl > rz_interval_threshold then
		log("[prefill] root zone file valid for %s, reusing data from disk",
			display_delay(file_ttl))
	else
		local ok, errmsg = pcall(download, rz_url, rz_local_fname)
		if not ok then
			rz_cur_interval = rz_https_fail_interval
						- math.random(rz_interval_randomizator_limit)
			log("[prefill] cannot download new zone (%s), "
				.. "will retry root zone download in %s",
				errmsg, display_delay(rz_cur_interval))
			event.reschedule(rz_event_id, rz_cur_interval * sec)
			return
		end
		file_ttl = rz_default_interval
	end
	-- file is up to date, import
	-- import/filter function gets executed after resolver/module
	local ok, errmsg = pcall(import, rz_local_fname)
	if not ok then
		rz_cur_interval = rz_no_ta_interval
					- math.random(rz_interval_randomizator_limit)
		log("[prefill] root zone import failed (%s), retry in %s",
			errmsg, display_delay(rz_cur_interval))
	else
		-- re-download before TTL expires
		rz_cur_interval = (file_ttl - rz_interval_threshold
					- math.random(rz_interval_randomizator_limit))
		log("[prefill] root zone refresh in %s",
			display_delay(rz_cur_interval))
	end
	event.reschedule(rz_event_id, rz_cur_interval * sec)
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

-- process one item from configuration table
-- right now it supports only root zone because
-- prefill module uses global variables
local function config_zone(zone_cfg)
	if zone_cfg.interval then
		zone_cfg.interval = tonumber(zone_cfg.interval)
		if zone_cfg.interval < rz_interval_min then
			error(string.format('[prefill] refresh interval %d s is too short, '
				.. 'minimal interval is %d s',
				zone_cfg.interval, rz_interval_min))
		end
		rz_default_interval = zone_cfg.interval
		rz_cur_interval = zone_cfg.interval
	end

	if not zone_cfg.ca_file then
		error('[prefill] option ca_file must point '
			.. 'to a file with CA certificate(s) in PEM format')
	end
	rz_ca_file = zone_cfg.ca_file

	if not zone_cfg.url or not string.match(zone_cfg.url, '^https://') then
		error('[prefill] option url must contain a '
			.. 'https:// URL of a zone file')
	else
		rz_url = zone_cfg.url
	end
end

function prefill.config(config)
	local root_configured = false
	if not config or type(config) ~= 'table' then
		error('[prefill] configuration must be in table '
			.. '{owner name = {per-zone config}}')
	end
	for owner, zone_cfg in pairs(config) do
		if owner ~= '.' then
			error('[prefill] only root zone can be imported '
				.. 'at the moment')
		else
			config_zone(zone_cfg)
			root_configured = true
		end
	end
	if not root_configured then
		error('[prefill] this module version requires configuration '
			.. 'for root zone')
	end

	-- ability to change intervals
	prefill.deinit()
	rz_event_id = event.after(0, timer)
end

return prefill
