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
	same('true', table_print(true), 'table_print handles true')
	test_de_serialization_autodesc(false)
	same('false', table_print(false), 'table_print handles false')
end

local function test_nil()
	test_de_serialization_autodesc(nil)
	same('nil', table_print(nil), 'table_print handles nil')
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
	same('0', table_print(0), 'table_print handles 0')
	test_de_serialization_autodesc(-math.huge)
	same('-inf', table_print(-math.huge), 'table_print handles -infinity')
	test_de_serialization_autodesc(math.huge)
	same('inf', table_print(math.huge), 'table_print handles +infinity')
	test_de_serialization_autodesc(tonumber('nan'))
	same('nan', table_print(tonumber('nan')), 'table_print handles nan')
	for _=1,20 do  -- integers
		test_de_serialization_autodesc(gen_number_int())
		-- bigger numbers might end up with non-exact representation
		local smallnumber = math.random(-2^32, 2^32)
		same(tostring(smallnumber), table_print(smallnumber),
			'table_print handles small numbers')
	end
	for _=1,20 do  -- floats
		local float = math.random()
		same(tostring(float), table_print(float),
			'table_print handles floats')
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

local marker = 'this string must be present somewhere in output'
local function gen_marker()
	return marker
end

local kluautil = require('kluautil')
local function random_modify_table(t, always, generator)
	assert(generator)
	local tab_len = kluautil.kr_table_len(t)
	local modified = false
	-- modify some values
	for key, val in pairs(t) do
		if math.random(1, tab_len) == 1 then
			if type(val) == 'table' then
				modified = modified or random_modify_table(val, false, generator)
			else
				t[key] = generator()
				modified = true
			end
		end
	end
	if always and not modified then
		-- fallback, add an unsupported key
		t[generator()] = true
		modified = true
	end
	return modified
end

local function test_table_supported()
	for i=1,20 do
		local t = gen_test_tables_supported()
		test_de_serialization(t, 'random table no. ' .. i)
		assert(random_modify_table(t, true, gen_marker))
		local str = table_print(t)
		ok(string.find(str, marker, 1, true),
			'table_print works on complex serializable tables')
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
				.. 'comment mode returned a string',
				desc))
		ok(string.find(output, '--', 1, true),
			'returned string contains a comment')
		output = table_print(val)
		same('string', type(output),
			string.format('table_print can stringify %s', desc))
		if type(val) ~= 'table' then
			ok(string.find(output, type(val), 1, true),
				'exotic type is mentioned in table_print output')
		end
	end
end

local function gen_test_tables_unsupported()
	local t = gen_test_tables_supported()
	random_modify_table(t, true, gen_unsupported_atomic)
	return t
end

local function test_unsupported_table()
	for i=1,20 do
		local t = gen_test_tables_unsupported()
		test_unsupported(t, 'random unsupported table no. ' .. i)()
		assert(random_modify_table(t, true, gen_marker))
		local str = table_print(t)
		ok(string.find(str, marker, 1, true),
			'table_print works on complex unserializable tables')
	end
end

local function func_2vararg_5ret(arg1, arg2, ...)
	return select('#', ...), nil, arg1 + arg2, false, nil
end
local function func_ret_nil() return nil end
local function func_ret_nothing() return end

local function test_pprint_func()
	local t = { [false] = func_2vararg_5ret }
	local output = table_print(t)
	ok(string.find(output, 'function false(arg1, arg2, ...)', 1, true),
		'function parameters are pretty printed')
end

local function test_pprint_func_ret()
	local output = table_print(func_2vararg_5ret(1, 2, 'bla'))
	local exp = [[
1	-- result # 1
nil	-- result # 2
3	-- result # 3
false	-- result # 4
nil	-- result # 5]]
	same(output, exp, 'multiple return values are pretty printed')

	output = table_print(func_ret_nil())
	same(output, 'nil', 'single return value does not have extra comments')

	output = table_print(func_ret_nothing())
	same(output, nil, 'no return values to be printed cause nil output')
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
	test_unsupported_table,
	test_pprint_func,
	test_pprint_func_ret,
}
