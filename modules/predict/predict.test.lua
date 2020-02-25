-- SPDX-License-Identifier: GPL-3.0-or-later
-- setup resolver
modules = { 'predict' }

-- mock global functions
local resolve_count = 0
local current_epoch = 0

resolve = function ()
	resolve_count = resolve_count + 1
end

stats.frequent = function ()
	return {
		{name = 'example.com', type = 'TYPE65535'},
		{name = 'example.com', type = 'SOA'},
	}
end

predict.epoch = function ()
	return current_epoch % predict.period + 1
end

-- test if draining of prefetch queue works
local function test_predict_drain()
	resolve_count = 0
	predict.queue_len = 2
	predict.queue['TYPE65535 example.com'] = 1
	predict.queue['SOA example.com'] = 1
	predict.drain()
	-- test that it attempted to prefetch
	same(resolve_count, 2, 'attempted to prefetch on drain')
	same(predict.queue_len, 0, 'prefetch queue empty after drain')
end

-- test if prediction process works
local function test_predict_process()
	-- start new epoch
	predict.process()
	same(predict.queue_len, 0, 'first epoch, empty prefetch queue')
	-- next epoch, still no period for frequent queries
	current_epoch = current_epoch + 1
	predict.process()
	same(predict.queue_len, 0, 'second epoch, empty prefetch queue')
	-- next epoch, found period
	current_epoch = current_epoch + 1
	predict.process()
	same(predict.queue_len, 2, 'third epoch, prefetching')
	-- drain works with scheduled prefetches (two batches)
	resolve_count = 0
	predict.drain()
	predict.drain()
	same(resolve_count, 2, 'attempted to resolve queries in queue')
	same(predict.queue_len, 0, 'prefetch queue is empty')
end

-- return test set
return {
	test_predict_drain,
	test_predict_process
}
