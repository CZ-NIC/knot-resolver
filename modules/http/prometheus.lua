-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module implementation
local M = {
	namespace = '',
	finalize = function (_ --[[metrics]]) end,
}

-- Gauge metrics
local gauges = {
	['worker.concurrent'] = true,
	['worker.rss']        = true,
}

local function merge(t, results, prefix)
	for _, result in pairs(results) do
		if type(result) == 'table' then
			for k, v in pairs(result) do
				local val = t[prefix..k]
				t[prefix..k] = (val or 0) + v
			end
		end
	end
end

local function getstats()
	local t = {}
	merge(t, map 'stats.list()', '')
	merge(t, map 'cache.stats()', 'cache.')
	merge(t, map 'worker.stats()', 'worker.')
	return t
end

-- @returns current stats + difference against previous data set passed in @param prev
local function snapshot_start(prev)
	assert(type(prev) == 'table', 'table with previous values expected')
	local is_empty = true
	-- Get current snapshot
	local cur, stats_dt = getstats(), {}
	for k,v in pairs(cur) do
		if gauges[k] then
			stats_dt[k] = v
		else
			stats_dt[k] = v - (prev[k] or 0)
		end
		is_empty = is_empty and stats_dt[k] == 0
	end
	-- Calculate upstreams and geotag them if possible
	local upstreams
	if http.geoip then
		upstreams = stats.upstreams()
		for k,v in pairs(upstreams) do
			local gi
			if string.find(k, '.', 1, true) then
				gi = http.geoip:search_ipv4(k)
			else
				gi = http.geoip:search_ipv6(k)
			end
			if gi then
				upstreams[k] = {data=v, location=gi.location, country=gi.country and gi.country.iso_code}
			end
		end
	end
	-- Aggregate per-worker metrics
	local wdata = {}
	for _, info in pairs(map 'worker.info()') do
		if type(info) == 'table' then
			wdata[tostring(info.pid)] = {
				rss = info.rss,
				usertime = info.usertime,
				systime = info.systime,
				pagefaults = info.pagefaults,
				queries = info.queries
			}
		end
	end
	-- Publish stats updates periodically
	if not is_empty then
		local update = {time=os.time(), stats=stats_dt, upstreams=upstreams, workers=wdata}
		return cur, update
	end
	return cur, nil
end

-- Function to sort frequency list
local function stream_stats(_, ws)
	local ok = true
	-- Publish stats updates periodically
	local prev = getstats()
	while ok do
		worker.sleep(1)
		local update
		prev, update = snapshot_start(prev)
		local push = tojson(update)
		ok = ws:send(push)
	end
end

-- Render stats in Prometheus text format
local function serve_prometheus()
	-- First aggregate metrics list and print counters
	local slist, render = getstats(), {}
	local latency = {}
	local counter = '# TYPE %s counter\n%s %f'
	for k,v in pairs(slist) do
		-- Transform Graphite tags into Prometheus labels
		-- See: https://gitlab.nic.cz/knot/knot-resolver/-/issues/650
		local k_index, k_len, k_tag = 0, #k, 0
		k = select(1, k:gsub('.', function (c)
			k_index = k_index + 1
			if k_tag == 0 then
				if c == '.' then return '_' end
				if c == ';' then k_tag = 1; return '{' end
			elseif k_tag == 1 then
				if k_index == k_len then
					if c == '=' then return '=""}'
					else return c .. '"}' end
				end
				if c == '=' then k_tag = 2; return '="' end
			elseif k_tag == 2 then
				if k_index == k_len then
					if c == ';' then return '"}'
					else return c .. '"}' end
				end
				if c == ';' then k_tag = 1; return '",' end
			end
			return nil
		end))
		-- Aggregate histograms
		local band = k:match('answer_([%d]+)ms')
		if band then
			table.insert(latency, {band, v})
		elseif k == 'answer_slow' then
			table.insert(latency, {'+Inf', v})
		-- Counter as a fallback
		else
			local key = M.namespace .. k
			local metric, label = key:match('^([^{]+)(.*)$')
			table.insert(render, string.format(counter, metric, metric .. label, v))
		end
	end
	-- Fill in latency histogram
	local function kweight(x) return tonumber(x) or math.huge end
	table.sort(latency, function (a,b) return kweight(a[1]) < kweight(b[1]) end)
	table.insert(render, string.format('# TYPE %slatency histogram', M.namespace))
	local count, sum = 0.0, 0.0
	for _,e in ipairs(latency) do
		-- The information about the %Inf bin is lost, so we treat it
		-- as a timeout (3000ms) for metrics purposes
		count = count + e[2]
		sum = sum + e[2] * (math.min(tonumber(e[1]), 3000.0))
		table.insert(render, string.format('%slatency_bucket{le="%s"} %f', M.namespace, e[1], count))
	end
	table.insert(render, string.format('%slatency_count %f', M.namespace, count))
	table.insert(render, string.format('%slatency_sum %f', M.namespace, sum))
	-- Finalize metrics table before rendering
	if type(M.finalize) == 'function' then
		M.finalize(render)
	end
	return table.concat(render, '\n') .. '\n'
end

-- Export module interface
M.endpoints = {
	['/stats']     = {'application/json', getstats, stream_stats},
	['/frequent']  = {'application/json', function () return stats.frequent() end},
	['/upstreams'] = {'application/json', function () return stats.upstreams() end},
	['/bogus']     = {'application/json', function () return bogus_log.frequent() end},
	['/metrics']   = {'text/plain; version=0.0.4', serve_prometheus},
}

return M
