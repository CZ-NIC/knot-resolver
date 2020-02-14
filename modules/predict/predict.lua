-- SPDX-License-Identifier: GPL-3.0-or-later
-- Speculative prefetching for repetitive and soon-expiring records to reduce latency.
-- @module predict
-- @field queue queue of scheduled queries
-- @field queue_len number of scheduled queries
-- @field period length of prediction history (number of windows)
-- @field window length of the prediction window
local predict = {
	queue = {},
	queue_len = 0,
	batch = 0,
	period = 24,
	window = 15,
	log = {},
}


-- Calculate next sample with jitter [1-2/5 of window]
local function next_event()
	local jitter = (predict.window * minute) / 5;
	return math.random(jitter, 2 * jitter)
end

-- Calculate current epoch (which window fits current time)
function predict.epoch()
	if not predict.period or predict.period <= 1 then return nil end
	return (os.date('%H')*(60/predict.window) +
		math.floor(os.date('%M')/predict.window)) % predict.period + 1
end

-- Resolve queued records and flush the queue
function predict.drain()
	local deleted = 0
	for key, _ in pairs(predict.queue) do
		local qtype, qname = key:match('(%S*)%s(.*)')
		resolve(qname, kres.type[qtype], kres.class.IN, {'NO_CACHE'})
		predict.queue[key] = nil
		deleted = deleted + 1
		-- Resolve smaller batches at a time
		if predict.batch > 0 and deleted >= predict.batch then
			break
		end
	end
	-- Schedule prefetch of another batch if not complete
	if predict.ev_drain then event.cancel(predict.ev_drain) end
	predict.ev_drain = nil
	if deleted > 0 then
		predict.ev_drain = event.after((predict.window * 3) * sec, predict.drain)
	end
	predict.queue_len = predict.queue_len - deleted
	stats['predict.queue'] = predict.queue_len
	collectgarbage('step')
	return 0
end

-- Enqueue queries from same format as predict.queue or predict.log
local function enqueue_from_log(current)
	if not current then return 0 end
	local queued = 0
	for key, val in pairs(current) do
		if val and not predict.queue[key] then
			predict.queue[key] = val
			queued = queued + 1
		end
	end
	return queued
end

-- Sample current epoch, return number of sampled queries
function predict.sample(epoch_now)
	if not epoch_now then return 0, 0 end
	local current = predict.log[epoch_now] or {}
	local queries = stats.frequent()
	stats.clear_frequent()
	local nr_samples = #queries
	for i = 1, nr_samples do
		local entry = queries[i]
		local key = string.format('%s %s', entry.type, entry.name)
		current[key] = 1
	end
	predict.log[epoch_now] = current
	return nr_samples
end

-- Predict queries for the upcoming epoch
local function generate(epoch_now)
	if not epoch_now then return 0 end
	local queued = 0
	for i = 1, predict.period / 2 - 1 do
		local current = predict.log[(epoch_now - i - 1) % predict.period + 1]
		local past = predict.log[(epoch_now - 2*i - 1) % predict.period + 1]
		if current and past then
			for k, _ in pairs(current) do
				if past[k] ~= nil and not predict.queue[k] then
					queued = queued + 1
					predict.queue[k] = 1
				end
			end
		end
	end
	return queued
end

function predict.process()
	-- Start a new epoch, or continue sampling
	local epoch_now = predict.epoch()
	local nr_queued = 0

	-- End of epoch
	if predict.current_epoch ~= epoch_now then
		stats['predict.epoch'] = epoch_now
		predict.current_epoch = epoch_now
		-- enqueue records from upcoming epoch
		nr_queued = enqueue_from_log(predict.log[epoch_now])
		-- predict next epoch
		nr_queued = nr_queued + generate(epoch_now)
		-- clear log for new epoch
		predict.log[epoch_now] = {}
	end

	-- Sample current epoch
	local nr_learned = predict.sample(epoch_now)

	-- Dispatch predicted queries
	if nr_queued > 0 then
		predict.queue_len = predict.queue_len + nr_queued
		predict.batch = predict.queue_len / 5
		if not predict.ev_drain then
			predict.ev_drain = event.after(0, predict.drain)
		end
	end

	if predict.ev_sample then event.cancel(predict.ev_sample) end
	predict.ev_sample = event.after(next_event(), predict.process)
	if stats then
		stats['predict.queue'] = predict.queue_len
		stats['predict.learned'] = nr_learned
	end
	collectgarbage()
end

function predict.init()
	if predict.window > 0 then
		predict.current_epoch = predict.epoch()
		predict.ev_sample = event.after(next_event(), predict.process)
	end
end

function predict.deinit()
	if predict.ev_sample then event.cancel(predict.ev_sample) end
	if predict.ev_drain then event.cancel(predict.ev_drain) end
	predict.ev_sample = nil
	predict.ev_drain = nil
	predict.log = {}
	predict.queue = {}
	predict.queue_len = 0
	collectgarbage()
end

function predict.config(config)
	-- Reconfigure
	config = config or {}
	if type(config) ~= 'table' then
		error('[predict] configuration must be a table or nil')
	end
	if config.window then predict.window = config.window end
	if config.period then predict.period = config.period end
	-- Load dependent modules
	if (predict.period or 0) ~= 0 and not stats then modules.load('stats') end
	-- Reinitialize to reset timers
	predict.deinit()
	predict.init()
end

predict.layer = {
	-- Prefetch all expiring (sub-)queries immediately after the request finishes.
	-- Doing that immediately is simplest and avoids creating (new) large bursts of activity.
	finish = function (_, req)
		local qrys = req.rplan.resolved
		for i = 0, (tonumber(qrys.len) - 1) do -- size_t doesn't work for some reason
			local qry = qrys.at[i]
			if qry.flags.EXPIRING == true then
				resolve(kres.dname2str(qry.sname), qry.stype, qry.sclass, {'NO_CACHE'})
			end
		end
	end
}

return predict
