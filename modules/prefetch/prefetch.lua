-- Speculative prefetching for repetitive and soon-expiring records to reduce latency.
-- @module prefetch
-- @field queue table of scheduled records
-- @field queue_max maximum length of the queue
-- @field window length of the coalescing window
local prefetch = {
	queue = {},
	queue_len = 0,
	batch = 0,
	epoch = 0,
	period = 24,
	window = 10,
	sample = 0,
	log = {}
}

-- Calculate current epoch (which window fits current time)
local function current_epoch()
	return (os.date('%H')*(60/prefetch.window) + math.floor(os.date('%M')/prefetch.window)) % prefetch.period + 1
end

-- Calculate next sample with jitter [1/5 +20% of window]
local function next_event()
	local jitter = (prefetch.window * minute) / 5;
	return math.random(jitter, 1.2 * jitter)
end

-- Resolve queued records and flush the queue
function prefetch.drain(ev)
	local deleted = 0
	for key, val in pairs(prefetch.queue) do
		worker.resolve(string.sub(key, 2), string.byte(key))
		prefetch.queue[key] = nil
		deleted = deleted + 1
		if deleted >= prefetch.batch then
			break
		end
	end
	if deleted > 0 then
		event.after((prefetch.window * 6) * sec, prefetch.drain)
	end
	prefetch.queue_len = prefetch.queue_len - deleted
	stats['predict.queue'] = prefetch.queue_len
	collectgarbage()
	return 0
end

-- Enqueue queries from set
local function enqueue(queries)
	local queued = 0
	local nr_queries = #queries
	for i = 1, nr_queries do
		local entry = queries[i]
		local key = string.char(entry.type)..entry.name
		if not prefetch.queue[key] then
			prefetch.queue[key] = 1
			queued = queued + 1
		end
	end
	return queued	
end

-- Prefetch soon-to-expire records
local function refresh()
	local queries = stats.expiring()
	stats.clear_expiring()
	return enqueue(queries)
end

-- Sample current epoch, return number of sampled queries
local function sample(epoch_now)
	local queries = stats.frequent()
	stats.clear_frequent()
	local queued = 0
	local current = prefetch.log[epoch_now]
	if prefetch.epoch ~= epoch_now or current == nil then
		if current ~= nil then
			queued = enqueue(current)
		end
		current = {}
	end
	local nr_samples = #queries
	for i = 1, nr_samples do
		local entry = queries[i]
		local key = string.char(entry.type)..entry.name
		current[key] = entry.count
	end
	prefetch.log[epoch_now] = current
	prefetch.sample = prefetch.sample + 1
	return nr_samples, queued
end

-- Sample current epoch, return number of sampled queries
local function predict(epoch_now)
	local queued = 0
	local period = prefetch.period + 1
	for i = 1, prefetch.period / 2 - 1 do
		local current = prefetch.log[(epoch_now - i) % period]
		local past = prefetch.log[(epoch_now - 2*i) % period]
		if current and past then
			for k, v in pairs(current) do
				if past[k] ~= nil and not prefetch.queue[k] then
					queued = queued + 1
					prefetch.queue[k] = 1
				end
			end
		end
	end
	return queued
end

-- Process current epoch
function prefetch.process(ev)
	-- Start a new epoch, or continue sampling
	local epoch_now = current_epoch()
	local nr_learned, nr_queued = sample(epoch_now)
	-- End of epoch, predict next
	if prefetch.epoch ~= epoch_now then
		prefetch.epoch = epoch_now
		prefetch.sample = 0
		nr_queued = nr_queued + predict(epoch_now)
	end
	-- Prefetch expiring records
	nr_queued = nr_queued + refresh()
	-- Dispatch prefetch requests
	if nr_queued > 0 then
		prefetch.queue_len = prefetch.queue_len + nr_queued
		prefetch.batch = prefetch.queue_len / 5
		event.after(0, prefetch.drain)
	end
	event.after(next_event(), prefetch.process)
	stats['predict.epoch'] = epoch_now
	stats['predict.queue'] = prefetch.queue_len
	stats['predict.learned'] = nr_learned
	collectgarbage()
end

function prefetch.init(module)
	prefetch.epoch = current_epoch()
	event.after(next_event(), prefetch.process)
end

function prefetch.deinit(module)
	if prefetch.ev then event.cancel(prefetch.ev) end
end

return prefetch
