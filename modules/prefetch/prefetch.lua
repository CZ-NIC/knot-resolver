-- Batch soon-expiring records in a queue and fetch them periodically.
-- This helps to reduce a latency for records that are often accessed.
-- @module prefetch
-- @field queue table of scheduled records
-- @field queue_max maximum length of the queue
-- @field queue_len current length of the queue
-- @field window length of the coalescing window
local prefetch = {
	queue = {},
	queue_max = 1000,
	queue_len = 0,
	window = 30,
	layer = {
		-- Schedule cached entries that are expiring soon
		finish = function(state, req, answer)
			local qry = kres.query_resolved(req)
			if not kres.query.has_flag(qry, kres.query.EXPIRING) then
				return state
			end
			-- Refresh entries that probably expire in this time window
			local qlen = prefetch.queue_len
			if qlen > prefetch.queue_max then
				return state
			end
			-- Key: {qtype [1], qname [1-255]}
			local key = string.char(answer:qtype())..answer:qname()
			local val = prefetch.queue[key]
			if not val then
				prefetch.queue[key] = 1
				prefetch.queue_len = qlen + 1
			else
				prefetch.queue[key] = val + 1
			end
			return state
		end
	}
}

-- Resolve queued records and flush the queue
function prefetch.batch(module)
	-- Defer prefetching if the server is loaded
	if worker.stats().concurrent > 10 then
		return 0
	end
	local to_delete = prefetch.queue_max / 5
	local deleted = 0
	for key, val in pairs(prefetch.queue) do
		worker.resolve(string.sub(key, 2), string.byte(key))
		prefetch.queue[key] = nil
		deleted = deleted + 1
		if deleted == to_delete then
			break
		end
	end
	prefetch.queue_len = prefetch.queue_len - deleted
	return 0
end

function prefetch.init(module)
	event.recurrent(prefetch.window * sec, prefetch.batch)
end

function prefetch.deinit(module)
	if prefetch.ev then event.cancel(prefetch.ev) end
end

return prefetch
