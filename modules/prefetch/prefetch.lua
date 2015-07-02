local prefetch = {
	queue = {},
	frequency = 2
}

-- @function Block layer implementation
prefetch.layer = {
	produce = function(state, req, pkt)
		-- Schedule cached entries that are expiring soon
		local qry = kres.query_current(req)
		if not kres.query_has_flag(qry, kres.query.CACHED) then
			return state
		end
		local rr = pkt:get(kres.ANSWER, 0)
		if rr and rr.ttl > 0 and rr.ttl < prefetch.frequency then
			local key = rr.owner..rr.type
			local val = prefetch.queue[key]
			if not val then
				prefetch.queue[key] = 1
			else
				prefetch.queue[key] = val + 1
			end
		end
		return state
	end
}

function prefetch.batch(module)
	for key, val in pairs(prefetch.queue) do
		print('prefetching',key,val)
	end
	prefetch.queue = {}
	-- @TODO: next batch interval
	event.after(prefetch.frequency * sec, prefetch.batch)
end

function prefetch.init(module)
	event.after(prefetch.frequency * sec, prefetch.batch)
end

function prefetch.deinit(module)
	if prefetch.ev then event.cancel(prefetch.ev) end
end

return prefetch
