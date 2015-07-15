-- Speculative prefetching for repetitive and soon-expiring records to reduce latency.
-- @module prefetch
-- @field queue table of scheduled records
-- @field queue_max maximum length of the queue
-- @field window length of the coalescing window
local prefetch = {
	queue = {},
	batch = 0,
	epoch = 0,
	period = 4 * 24,
	window = 15,
	log = {}
}

-- Calculate current epoch (number of quarter-hours today)
local function current_epoch()
	return os.date('%H')*(60/prefetch.window) + math.floor(os.date('%M')/prefetch.window) + 1
end

-- Resolve queued records and flush the queue
function prefetch.dispatch(ev)
	-- Defer prefetching if the server is loaded
	if worker.stats().concurrent > 10 then
		event.after(minute, prefetch.dispatch)
		prefetch.batch = prefetch.batch + prefetch.batch / 2
		return 0
	end
	local deleted = 0
	for key, val in pairs(prefetch.queue) do
		worker.resolve(string.sub(key, 2), string.byte(key))
		if val > 1 then
			prefetch.queue[key] = val - 1
		else
			prefetch.queue[key] = nil
		end
		deleted = deleted + 1
		if deleted == prefetch.batch then
			break
		end
	end
	if deleted > 0 then
		event.after(minute, prefetch.dispatch)
	end
	return 0
end

-- Process current epoch
function prefetch.process(ev)
	-- Process current learning epoch
	local start = os.clock()
	local recent_queries = stats.queries()
	stats.queries_clear()
	local current = {}
	for i = 1, #recent_queries do
		local entry = recent_queries[i]
		local key = string.char(entry.type)..entry.name
		current[key] = entry.count
		-- print('.. learning', entry.name, entry.type)
	end
	print (string.format('[prob] learned epoch: %d, %.2f sec', prefetch.epoch, os.clock() - start))
	prefetch.log[prefetch.epoch] = current
	prefetch.epoch = prefetch.epoch % prefetch.period + 1
	-- Predict queries for the next epoch based on the usage patterns
	for i = 1, prefetch.period / 2 - 1 do
		current = prefetch.log[prefetch.epoch - i]
		local past = prefetch.log[prefetch.epoch - 2*i]
		if current and past then
			for k, v in pairs(current) do
				if past[k] ~= nil then
					prefetch.queue[k] = v
				end
			end
		end
	end
	print (string.format('[prob] predicted epoch: %d, %.2f sec', prefetch.epoch, os.clock() - start))
	-- TODO: batch in soon-expiring queries
	-- TODO: clusterize records often found together
	-- Dispatch prefetch requests
	prefetch.batch = #prefetch.queue / prefetch.window
	event.after(0, prefetch.dispatch)
end

function prefetch.init(module)
	prefetch.epoch = current_epoch()
	event.recurrent(prefetch.window * minute, prefetch.process)
end

function prefetch.deinit(module)
	if prefetch.ev then event.cancel(prefetch.ev) end
end

return prefetch
