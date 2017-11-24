function fail(fmt, ...)
	io.stderr:write(string.format(fmt..'\n', ...))
	os.exit(2)
end

function test(f, ...)
	local res, exception = pcall(f, ...)
	if not res then
		local trace = debug.getinfo(2)
		fail('%s:%d %s', trace.source, trace.currentline, exception)
	end
	return res
end

function table_keys_to_lower(table)
	local res = {}
	for k, v in pairs(table) do
		res[k:lower()] = v
	end
	return res
end

function contains(table, value)
	for _, v in pairs(table) do
		if v == value then
			return true
		end
	end
	return false
end

-- Emulate busted testing interface
local assert_builtin = assert
assert = setmetatable({}, {
	__call = function (_, ...)
		return assert_builtin(...)
	end,
	__index = {
		truthy = function (expr)
			assert_builtin(expr)
		end,
		falsy = function (expr)
			assert_builtin(not expr)
		end,
		same = function (a, b)
			if a ~= b then
				assert_builtin(false, string.format('expected: %s got: %s', a, b))
			end
		end,
	}
})