local cqueues = require('cqueues')

-- Load dependent modules
if not stats then modules.load('stats') end

local function getstats()
	local t = stats.list()
	for k,v in pairs(cache.stats()) do t['cache.'..k] = v end
	for k,v in pairs(worker.stats()) do t['worker.'..k] = v end
	return t
end

-- Function to sort frequency list
local function stream_stats(h, ws)
	local ok, prev = true, getstats()
	while ok do
		-- Get current snapshot
		local cur, stats_dt = getstats(), {}
		for k,v in pairs(cur) do
			stats_dt[k] = v - (prev[k] or 0)
		end
		prev = cur
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
		-- Publish stats updates periodically
		local push = tojson({stats=stats_dt,upstreams=upstreams or {}})
		ok = ws:send(push)
		cqueues.sleep(1)
	end
end

-- Render stats in Prometheus text format
local function serve_prometheus()
	-- First aggregate metrics list and print counters
	local slist, render = getstats(), {}
	local latency = {}
	local counter = '# TYPE %s counter\n%s %f'
	for k,v in pairs(slist) do
		k = select(1, k:gsub('%.', '_'))
		-- Aggregate histograms
		local band = k:match('answer_([%d]+)ms')
		if band then
			table.insert(latency, {band, v})
		elseif k == 'answer_slow' then
			table.insert(latency, {'+Inf', v})
		-- Counter as a fallback
		else table.insert(render, string.format(counter, k, k, v)) end
	end
	-- Fill in latency histogram
	local function kweight(x) return tonumber(x) or math.huge end
	table.sort(latency, function (a,b) return kweight(a[1]) < kweight(b[1]) end)
	table.insert(render, '# TYPE latency histogram')
	local count, sum = 0.0, 0.0
	for _,e in ipairs(latency) do
		-- The information about the %Inf bin is lost, so we treat it
		-- as a timeout (3000ms) for metrics purposes
		count = count + e[2]
		sum = sum + e[2] * (math.min(tonumber(e[1]), 3000.0))
		table.insert(render, string.format('latency_bucket{le=%s} %f', e[1], count))
	end
	table.insert(render, string.format('latency_count %f', count))
	table.insert(render, string.format('latency_sum %f', sum))
	return table.concat(render, '\n')
end

-- Export endpoints
return {
	['/stats']     = {'application/json', getstats, stream_stats},
	['/frequent']  = {'application/json', function () return stats.frequent() end},
	['/metrics']   = {'text/plain; version=0.0.4', serve_prometheus},
}