-- SPDX-License-Identifier: GPL-3.0-or-later
local M = {}

function M.test(f, ...)
	local res, exception = pcall(f, ...)
	if not res then
		local trace = debug.getinfo(2)
		io.stderr:write(string.format('%s:%d %s\n', trace.source, trace.currentline, exception))
		os.exit(2)
	end
	return res
end

function M.table_keys_to_lower(table)
	local res = {}
	for k, v in pairs(table) do
		res[k:lower()] = v
	end
	return res
end

local function contains(pass, fail, table, value, message)
	message = message or string.format('table contains "%s"', value)
	for _, v in pairs(table) do
		if v == value then
			pass(message)
			return
		end
	end
	fail(message)
	return
end

function M.contains(table, value, message)
	return contains(pass, fail, table, value, message)
end

function M.not_contains(table, value, message)
	return contains(fail, pass, table, value, message)
end

-- Resolve a name and check the answer.  Do *not* return until finished.
function M.check_answer(desc, qname, qtype, expected_rcode)
	qtype_str = kres.tostring.type[qtype]
	local done = false
	callback = function(pkt)
		same(pkt:rcode(), expected_rcode,
		     desc .. ': expecting answer for query ' .. qname .. ' ' .. qtype_str
		      .. ' with rcode ' .. kres.tostring.rcode[expected_rcode])

		ok((pkt:ancount() > 0) == (pkt:rcode() == kres.rcode.NOERROR),
		   desc ..': checking number of answers for ' .. qname .. ' ' .. qtype_str)
		done = true
	end
	resolve(qname, qtype, kres.class.IN, {}, callback)

	for delay = 0.1, 4, 0.5 do -- total max 14.9s in 8 steps
		if done then return end
		worker.sleep(delay)
	end
	if not done then fail('check_answer() timed out') end
end

return M
