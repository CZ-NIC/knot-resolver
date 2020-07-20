-- SPDX-License-Identifier: GPL-3.0-or-later

local serializer_class = {
	__inst_mt = {}
}
-- class instances with following metatable inherit all class members
serializer_class.__inst_mt.__index = serializer_class

-- constructor
function serializer_class.new(on_unrepresentable)
	on_unrepresentable = on_unrepresentable or 'comment'
	if not (on_unrepresentable == 'comment'
		or on_unrepresentable == 'error') then
		error('unsupported val2expr on_unrepresentable option ' .. tostring(on_unrepresentable))
	end
	local inst = {}
	inst.on_unrepresentable = on_unrepresentable
	inst.done = {}
	setmetatable(inst, serializer_class.__inst_mt)
	return inst
end

-- format comment with leading/ending whitespace if needed
local function format_note(note, ws_prefix, ws_suffix)
	if note == nil then
		return ''
	else
		return string.format('%s--[[ %s ]]%s',
			ws_prefix or '', note, ws_suffix or '')
	end
end

local function static_serializer(val, on_unrepresentable)
	local inst = serializer_class.new(on_unrepresentable)
	local expr, note = inst:val2expr(val)
	return string.format('%s%s', format_note(note, nil, ' '), expr)
end

function serializer_class.val2expr(self, val)
	local val_type = type(val)
	local val_repr = self[val_type]
	if val_repr then
		return val_repr(self, val)
	else  -- function, thread, userdata
		if self.on_unrepresentable == 'comment' then
			return 'nil', string.format('missing %s', val)
		elseif self.on_unrepresentable == 'error' then
			error(string.format('cannot print %s', val_type), 2)
		end
	end
end

serializer_class['nil'] = function(_, val)
	assert(type(val) == 'nil')
	return 'nil'
end

function serializer_class.number(_, val)
	assert(type(val) == 'number')
	if val == math.huge then
		return 'math.huge'
	elseif val == -math.huge then
		return '-math.huge'
	elseif tostring(val) == 'nan' then
		return 'tonumber(\'nan\')'
	else
		return string.format("%.60f", val)
	end
end

function serializer_class.string(_, val)
	assert(type(val) == 'string')
	val = tostring(val)
	local chars = {'\''}
	for i = 1, #val do
		local c = string.byte(val, i)
		-- ASCII (from space to ~) and not ' or \
		if (c >= 0x20 and c < 0x7f)
			and c ~= 0x27 and c ~= 0x5C then
			table.insert(chars, string.char(c))
		else
			table.insert(chars, string.format('\\%03d', c))
		end
	end
	table.insert(chars, '\'')
	return table.concat(chars)
end

function serializer_class.boolean(_, val)
	assert(type(val) == 'boolean')
	return tostring(val)
end

function serializer_class.table(self, tab)
	assert(type(tab) == 'table')
	if self.done[tab] then
		error('cyclic reference', 0)
	end
	self.done[tab] = true

	local items = {'{'}
	local previdx = 0
	for idx, val in pairs(tab) do
		local errors, valok, valexpr, valnote, idxok, idxexpr, idxnote
		errors = {}
		valok, valexpr, valnote = pcall(self.val2expr, self, val)
		if not valok then
			table.insert(errors, string.format('value: %s', valexpr))
		end

		local addidx
		if previdx and type(idx) == 'number' and idx - 1 == previdx then
			-- monotonic sequence, do not print key
			previdx = idx
			addidx = false
		else
			-- end of monotonic sequence
			-- from now on print keys as well
			previdx = nil
			addidx = true
		end

		if addidx then
			idxok, idxexpr, idxnote = pcall(self.val2expr, self, idx)
			if not idxok or idxexpr == 'nil' then
				table.insert(errors, string.format('key: not serializable', idxexpr))
			end
		end

		if #errors == 0 then
			-- finally serialize one [key=]?value expression
			if addidx then
				table.insert(items,
					string.format('%s[%s]', format_note(idxnote, nil, ' '), idxexpr))
				table.insert(items, '=')
			end
			table.insert(items, string.format('%s%s,', format_note(valnote, nil, ' '), valexpr))
		else
			local errmsg = string.format('%s = %s (%s)',
				tostring(idx),
				tostring(val),
				table.concat(errors, ', '))
			if self.on_unrepresentable == 'error' then
				error(errmsg, 0)
			else
				errmsg = string.format('--[[ missing %s ]]', errmsg)
				table.insert(items, errmsg)
			end
		end
	end  -- one key+value
	table.insert(items, '}')
	return table.concat(items, ' '), string.format('%s follows', tab)
end

local function deserialize_lua(serial)
	assert(type(serial) == 'string')
	local deserial_func = loadstring('return ' .. serial)
	if type(deserial_func) ~= 'function' then
		panic('input is not a valid Lua expression')
	end
	return deserial_func()
end

local M = {
	serialize_lua = static_serializer,
	deserialize_lua = deserialize_lua
}

return M
