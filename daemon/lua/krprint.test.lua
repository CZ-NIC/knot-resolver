local serialize_lua = require('krprint').serialize_lua
local deserialize_lua = require('krprint').deserialize_lua

local function gen_string(maxlen)
	maxlen = maxlen or 100
	local len = math.random(0, maxlen)
	local buf = {}
	for _=1,len do
		table.insert(buf, string.char(math.random(0, 255)))
	end
	return table.concat(buf)
end

local function test_de_serialization(orig_val, desc)
	local serial = serialize_lua(orig_val)
	ok(type(serial) == 'string' and #serial > 0,
		'serialization returns non-empty string: ' .. desc)
	local deserial_val = deserialize_lua(serial)
	same(type(orig_val), type(deserial_val),
		'deserialized value has the same type: ' .. desc)
	if type(orig_val) == 'number' then
		-- nan cannot be compared using == operator
		if tostring(orig_val) == 'nan' and tostring(deserial_val) == 'nan' then
			pass('nan value serialized and deserialized')
		elseif orig_val ~= math.huge and orig_val ~= -math.huge then
		-- tolerance measured experimentally on x86_64 LuaJIT 2.1.0-beta3
			local tolerance = 1e-14
			ok(math.abs(orig_val - deserial_val) <= tolerance,
				'deserialized number is within tolerance ' .. tolerance)
		else
			same(orig_val, deserial_val, 'deserialization returns the same infinity:' .. desc)
		end
	else
		same(orig_val, deserial_val,
			'deserialization returns the same value: ' .. desc)
	end
end

local function test_de_serialization_autodesc(orig_val)
	test_de_serialization(orig_val, tostring(orig_val))
end

local function test_bool()
	test_de_serialization_autodesc(true)
	test_de_serialization_autodesc(false)
end

local function test_nil()
	test_de_serialization_autodesc(nil)
end

local function gen_number_int()
	local number
	-- make "small" numbers more likely so they actually happen
	if math.random() < 0.5 then
		number = math.random(-2^32, 2^32)
	else
		number = math.random(-2^48, 2^48)
	end
	return number
end

local function gen_number_float()
	return math.random()
end

local function test_number()
	test_de_serialization_autodesc(0)
	test_de_serialization_autodesc(-math.huge)
	test_de_serialization_autodesc(math.huge)
	test_de_serialization_autodesc(tonumber('nan'))
	for _=1,20 do  -- integers
		test_de_serialization_autodesc(gen_number_int())
	end
	for _=1,20 do  -- floats
		test_de_serialization_autodesc(gen_number_float())
	end
end

local function test_string()
	test_de_serialization('', 'empty string')
	for _=1,20 do
		local str = gen_string(1024*10)
		test_de_serialization(str, 'random string length ' .. #str)
	end
end

local function gen_number()
	-- pure random would not produce special cases often enough
	local generators = {
		function() return 0 end,
		function() return -math.huge end,
		function() return math.huge end,
		gen_number_int,
		gen_number_float,
	}
	return generators[math.random(1, #generators)]()
end

local function gen_boolean()
	local options = {true, false}
	return options[math.random(1, #options)]
end

local function gen_table_atomic()
	-- nil keys or values are not allowed
	-- nested tables are handled elsewhere
	local supported_types = {
		gen_number,
		gen_string,
		gen_boolean,
	}
	val = supported_types[math.random(1, #supported_types)]()
	return val
end

local function gen_test_tables_supported(level)
	level = level or 1
	local max_level = 10
	local max_items_per_table = 30
	local t = {}
	for _=1, math.random(0, max_items_per_table) do
		local val_as_table = (level <= max_level) and math.random() < 0.1
		local key, val
		-- tapered.same method cannot compare keys with type table
		key = gen_table_atomic()
		if val_as_table then
			val = gen_test_tables_supported(level + 1)
		else
			val = gen_table_atomic()
		end
		t[key] = val
	end
	return t
end

function test_table_supported()
	for i=1,20 do
		local t = gen_test_tables_supported()
		test_de_serialization(t, 'random table no. ' .. i)
	end
end

local ffi = require('ffi')
local const_func = tostring
local const_thread = coroutine.create(tostring)
local const_userdata = ffi.C
local const_cdata = ffi.new('int')

local function gen_unsupported_atomic()
	-- nested tables are handled elsewhere
	local unsupported_types = {
		const_func,
		const_thread,
		const_userdata,
		const_cdata
	}
	val = unsupported_types[math.random(1, #unsupported_types)]
	return val
end

local function test_unsupported(val, desc)
	desc = desc or string.format('unsupported %s', type(val))
	return function()
		boom(serialize_lua, { val, 'error' }, string.format(
			'attempt to serialize %s in error mode '
			.. 'causes error', desc))
		local output = serialize_lua(val, 'comment')
		same('string', type(output),
			string.format('attempt to serialize %s in '
				.. 'comment mode provides returned a string',
				desc))
		ok(string.find(output, '--'), 'returned string contains a comment')
	end
end

local kluautil = require('kluautil')
local function make_table_unsupported(t, always)
	local tab_len = kluautil.kr_table_len(t)
	local modified = false
	-- modify some values
	for key, val in pairs(t) do
		if math.random(1, tab_len) == 1 then
			if type(val) == 'table' then
				modified = modifier or make_table_unsupported(val, false)
			else
				t[key] = gen_unsupported_atomic()
				modified = true
			end
		end
	end
	if always and not modified then
		-- fallback, add an unsupported key
		t[gen_unsupported_atomic()] = true
	end
	return modified
end

local function gen_test_tables_unsupported()
	local t = gen_test_tables_supported()
	make_table_unsupported(t, true)
	return t
end

local function test_unsupported_table()
	for i=1,20 do
		local t = gen_test_tables_unsupported()
		test_unsupported(t, 'random unsupported table no. ' .. i)()
	end
end

return {
	test_bool,
	test_nil,
	test_number,
	test_string,
	test_table_supported,
	test_unsupported(const_func),
	test_unsupported(const_thread),
	test_unsupported(const_userdata),
	test_unsupported(const_cdata),
	test_unsupported_table
}
