-- SPDX-License-Identifier: GPL-3.0-or-later
-- check prerequisites
if not worker.bg_worker then
	-- skipping worker test because it doesnt support background worker
	os.exit(77)
else
	-- import primitives for synchronisation
	local monotime = require('cqueues').monotime

	-- test whether sleeping works
	local function test_worker_sleep()
		local now = monotime()
		ok(pcall(worker.sleep, 0.1), 'sleep works')
		local elapsed = monotime() - now
		ok(elapsed > 0, 'sleep takes non-zero time')
	end

	-- helper to track number of executions
	local cv = require('cqueues.condition').new()
	local tasks = 0
	local function work ()
		worker.sleep(0.1)
		tasks = tasks - 1
		if tasks == 0 then
			cv:signal()
		elseif tasks < 0 then
			error('too many executions')
		end
	end

	-- test whether coroutines work
	local function test_worker_coroutine()
		tasks = 2
		worker.coroutine(work)
		worker.coroutine(work)
		-- Check if coroutines finish
		local status = cv:wait(1)
		same(tasks, 0, 'all coroutines finish')
		ok(status, 'coroutines finish successfully')
		-- Check if nesting coroutines works
		local now = monotime()
		tasks = 100
		worker.coroutine(function ()
			for _ = 1, 100 do
				worker.coroutine(work)
			end
		end)
		status = cv:wait(1)
		local elapsed = monotime() - now
		same(tasks, 0, 'all nested coroutines finish')
		ok(status, 'nested coroutines finish successfully')
		-- Test if 100 coroutines didnt execute synchronously
		-- (the wait time would be 100 * 0.1 = 10s sleep time)
		-- Concurrent sleep time should still be ~0.1s (added some safe margin)
		ok(elapsed < 0.5, 'coroutines didnt block while sleeping')
	end

	-- plan tests
	local tests = {
		test_worker_sleep,
		test_worker_coroutine
	}

	return tests
end
