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
function prefetch.dispatch(ev)
	local deleted = 0
	for key, val in pairs(prefetch.queue) do
		worker.resolve(string.sub(key, 2), string.byte(key))
		if val > 1 then
			prefetch.queue[key] = val - 1
		else
			prefetch.queue[key] = nil
		end
		deleted = deleted + 1
		if deleted >= prefetch.batch then
			break
		end
	end
	if deleted > 0 then
		event.after((prefetch.window * 6) * sec, prefetch.dispatch)
	end
	prefetch.queue_len = prefetch.queue_len - deleted
	stats['predict.queue'] = prefetch.queue_len
	collectgarbage()
	return 0
end

-- Sample current epoch, return number of sampled queries
local function sample(epoch_now)
	local queries = stats.frequent()
	stats.clear_frequent()
	local start = os.clock()
	local current = prefetch.log[epoch_now]
	if prefetch.epoch ~= epoch_now or current == nil then
		current = {}
	end
	local nr_samples = #queries
	for i = 1, nr_samples do
		local entry = queries[i]
		local key = string.char(entry.type)..entry.name
		current[key] = entry.count
	end
	print (string.format('[prob] .. sampling epoch: %d/%d, %.2f sec (%d items)', epoch_now, prefetch.sample, os.clock() - start, nr_samples))
	prefetch.log[epoch_now] = current
	prefetch.sample = prefetch.sample + 1
	return nr_samples
end

-- Prefetch soon-to-expire records
local function refresh()
	local queries = stats.expiring()
	stats.clear_expiring()
	local nr_samples = #queries
	for i = 1, nr_samples do
		local entry = queries[i]
		local key = string.char(entry.type)..entry.name
		prefetch.queue[key] = 1
	end
	print (string.format('[prob]    .. prefetching %d items', nr_samples))
	return nr_samples
end

-- Sample current epoch, return number of sampled queries
local function predict(epoch_now)
	local start = os.clock()
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
	print (string.format('[prob] predicted epoch: %d, %.2f sec (%d items)', epoch_now, os.clock() - start, queued))
	return queued
end

-- Process current epoch
function prefetch.process(ev)
	-- Start a new epoch, or continue sampling
	local epoch_now = current_epoch()
	local nr_learned = sample(epoch_now)
	local nr_queued = 0
	-- End of epoch, predict next
	if prefetch.epoch ~= epoch_now then
		prefetch.queue = {}
		prefetch.queue_len = 0
		prefetch.epoch = epoch_now
		prefetch.sample = 0
		nr_queued = nr_queued + predict(epoch_now)
		prefetch.queue_len = prefetch.queue_len + nr_queued
	end
	-- Prefetch expiring records
	nr_queued = nr_queued + refresh()
	-- Dispatch prefetch requests
	if nr_queued > 0 then
		prefetch.queue_len = prefetch.queue_len + nr_queued
		prefetch.batch = prefetch.queue_len / 5
		event.after(0, prefetch.dispatch)
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
