-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

local rz_url = "https://www.internic.net/domain/root.zone"
local rz_local_fname = "root.zone"
local rz_ca_file = nil
local rz_event_id = nil

local rz_default_interval = 86400
local rz_https_fail_interval = 600
local rz_import_error_interval = 600
local rz_cur_interval = rz_default_interval
local rz_interval_randomizer_limit = 10
local rz_interval_threshold = 5
local rz_interval_min = 3600

local rz_first_try = true

local prefill = {}

-- hack for circular dependency between timer() and fill_cache()
local forward_references = {}

local function stop_timer()
	if rz_event_id then
		event.cancel(rz_event_id)
		rz_event_id = nil
	end
end

local function timer()
	stop_timer()
	worker.bg_worker.cq:wrap(forward_references.fill_cache)
end

local function restart_timer(after)
	stop_timer()
	rz_event_id = event.after(after * sec, timer)
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
	local c_str = ffi.new("char[?]", #fname)
	ffi.copy(c_str, fname)
	local mtime = tonumber(ffi.C.kr_file_mtime(c_str))

	if mtime > 0 then
		local age = os.time() - mtime
		return math.max(
			rz_cur_interval - age,
			0)
	else
		return 0  -- file does not exist, download now
	end
end

local function download(url, fname)
	local kluautil = require('kluautil')
	local file, rcode, errmsg
	file, errmsg = io.open(fname, 'w')
	if not file then
		error(string.format("[prefil] unable to open file %s (%s)",
			fname, errmsg))
	end

	log_info(ffi.C.LOG_GRP_PREFILL, "downloading root zone to file %s ...", fname)
	rcode, errmsg = kluautil.kr_https_fetch(url, file, rz_ca_file)
	if rcode == nil then
		error(string.format("[prefil] fetch of `%s` failed: %s", url, errmsg))
	end

	file:close()
end

local function import(fname)
	local ret = ffi.C.zi_zone_import({
		zone_file = fname,
		time_src = ffi.C.ZI_STAMP_MTIM, -- the file might be slightly older
	})
	if ret == 0 then
		log_info(ffi.C.LOG_GRP_PREFILL, "zone successfully parsed, import started")
	else
		error(string.format(
			"[prefil] zone import failed: %s", ffi.C.knot_strerror(ret)
		))
	end
end

function forward_references.fill_cache()
	local file_ttl = get_file_ttl(rz_local_fname)

	if file_ttl > rz_interval_threshold then
		log_info(ffi.C.LOG_GRP_PREFILL, "root zone file valid for %s, reusing data from disk",
			display_delay(file_ttl))
	else
		local ok, errmsg = pcall(download, rz_url, rz_local_fname)
		if not ok then
			rz_cur_interval = rz_https_fail_interval
						- math.random(rz_interval_randomizer_limit)
			log_info(ffi.C.LOG_GRP_PREFILL, "cannot download new zone (%s), "
				.. "will retry root zone download in %s",
				errmsg, display_delay(rz_cur_interval))
			restart_timer(rz_cur_interval)
			os.remove(rz_local_fname)
			return
		end
		file_ttl = rz_default_interval
	end
	-- file is up to date, import
	-- import/filter function gets executed after resolver/module
	local ok, errmsg = pcall(import, rz_local_fname)
	if not ok then
		if rz_first_try then
			rz_first_try = false
			rz_cur_interval = 1
		else
			rz_cur_interval = rz_import_error_interval
				- math.random(rz_interval_randomizer_limit)
		end
		log_info(ffi.C.LOG_GRP_PREFILL, "root zone import failed (%s), retry in %s",
			errmsg, display_delay(rz_cur_interval))
	else
		-- re-download before TTL expires
		rz_cur_interval = (file_ttl - rz_interval_threshold
					- math.random(rz_interval_randomizer_limit))
		log_info(ffi.C.LOG_GRP_PREFILL, "root zone refresh in %s",
			display_delay(rz_cur_interval))
	end
	restart_timer(rz_cur_interval)
end

function prefill.deinit()
	stop_timer()
end

-- process one item from configuration table
-- right now it supports only root zone because
-- prefill module uses global variables
local function config_zone(zone_cfg)
	if zone_cfg.interval then
		zone_cfg.interval = tonumber(zone_cfg.interval)
		if zone_cfg.interval < rz_interval_min then
			error(string.format('[prefil] refresh interval %d s is too short, '
				.. 'minimal interval is %d s',
				zone_cfg.interval, rz_interval_min))
		end
		rz_default_interval = zone_cfg.interval
		rz_cur_interval = zone_cfg.interval
	end

	rz_ca_file = zone_cfg.ca_file

	if not zone_cfg.url or not string.match(zone_cfg.url, '^https://') then
		error('[prefil] option url must contain a '
			.. 'https:// URL of a zone file')
	else
		rz_url = zone_cfg.url
	end
end

function prefill.config(config)
	if config == nil then return end -- e.g. just modules = { 'prefill' }
	local root_configured = false
	if type(config) ~= 'table' then
		error('[prefil] configuration must be in table '
			.. '{owner name = {per-zone config}}')
	end
	for owner, zone_cfg in pairs(config) do
		if owner ~= '.' then
			error('[prefil] only root zone can be imported '
				.. 'at the moment')
		else
			config_zone(zone_cfg)
			root_configured = true
		end
	end
	if not root_configured then
		error('[prefil] this module version requires configuration '
			.. 'for root zone')
	end

	restart_timer(0)  -- start now
end

return prefill
