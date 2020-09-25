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

return M
