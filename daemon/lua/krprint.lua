-- SPDX-License-Identifier: GPL-3.0-or-later
local base_class = {
	cur_indent = 0,
}

-- shared constructor: use as serializer_class:new()
function base_class.new(class, on_unrepresentable)
	on_unrepresentable = on_unrepresentable or 'comment'
	if not (on_unrepresentable == 'comment'
		or on_unrepresentable == 'error') then
		error('unsupported val2expr on_unrepresentable option ' .. tostring(on_unrepresentable))
	end
	local inst = {}
	inst.on_unrepresentable = on_unrepresentable
	inst.done = {}
	setmetatable(inst, class.__inst_mt)
	return inst
end

-- format comment with leading/ending whitespace if needed
function base_class.format_note(self, note, ws_prefix, ws_suffix)
	if note == nil then
		return ''
	else
		return string.format('%s--[[ %s ]]%s',
			ws_prefix or '', note, ws_suffix or '')
	end
end

function base_class.indent_head(self)
	return string.rep(' ', self.cur_indent)
end

function base_class.indent_inc(self)
	self.cur_indent = self.cur_indent + self.indent_step
end

function base_class.indent_dec(self)
	self.cur_indent = self.cur_indent - self.indent_step
end

function base_class.val2expr(self, val)
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

-- "nil" is a Lua keyword so assignment below is workaround to create
-- function base_class.nil(self, val)
base_class['nil'] = function(_, val)
	assert(type(val) == 'nil')
	return 'nil'
end

function base_class.number(_, val)
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

function base_class.string(_, val)
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

function base_class.boolean(_, val)
	assert(type(val) == 'boolean')
	return tostring(val)
end

local function ordered_iter(unordered_tt)
	local keys = {}
	for k in pairs(unordered_tt) do
		table.insert(keys, k)
	end
	table.sort(keys,
		function (a, b)
			if type(a) ~= type(b) then
				return type(a) < type(b)
			end
			if type(a) == 'number' then
				return a < b
			else
				return tostring(a) < tostring(b)
			end
		end)
	local i = 0
	return function()
		i = i + 1
		if keys[i] ~= nil then
			return keys[i], unordered_tt[keys[i]]
		end
	end
end

function base_class.table(self, tab)
	assert(type(tab) == 'table')
	if self.done[tab] then
		error('cyclic reference', 0)
	end
	self.done[tab] = true

	local items = {'{'}
	local previdx = 0
	self:indent_inc()
	for idx, val in ordered_iter(tab) do
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

		local item = ''
		if #errors == 0 then
			-- finally serialize one [key=]?value expression
			local indent = self:indent_head()
			if addidx then
				item = string.format('%s%s[%s]%s=%s', indent, self:format_note(idxnote, nil, self.key_val_sep), idxexpr, self.key_val_sep, self.key_val_sep)
				indent = ''
			end
			item = item .. string.format('%s%s%s,', indent, self:format_note(valnote, nil, self.item_sep), valexpr)
		else
			local errmsg = string.format('%s = %s (%s)',
				tostring(idx),
				tostring(val),
				table.concat(errors, ', '))
			if self.on_unrepresentable == 'error' then
				error(errmsg, 0)
			else
				errmsg = string.format('--[[ missing %s ]]', errmsg)
				item = errmsg
			end
		end
		table.insert(items, item)
	end  -- one key+value
	self:indent_dec()
	table.insert(items, self:indent_head() .. '}')
	return table.concat(items, self.item_sep), string.format('%s follows', tab)
end

local serializer_class = {
	indent_step = 0,
	item_sep = ' ',
	key_val_sep = ' ',
	__inst_mt = {}
}
-- inhertance form base class (for :new())
setmetatable(serializer_class, { __index = base_class })
-- class instances with following metatable inherit all class members
serializer_class.__inst_mt.__index = serializer_class

local function static_serializer(val, on_unrepresentable)
	local inst = serializer_class:new(on_unrepresentable)
	local expr, note = inst:val2expr(val)
	return string.format('%s%s', inst:format_note(note, nil, inst.item_sep), expr)
	end

local pprinter_class = {
	indent_step = 4,
	item_sep = '\n',
	key_val_sep = ' ',
	__inst_mt = {},
	format_note = function() return '' end,
}

-- default tostring method is better suited for human-intended output
function pprinter_class.number(_, number)
	return tostring(number)
end

local function deserialize_lua(serial)
	assert(type(serial) == 'string')
	local deserial_func = loadstring('return ' .. serial)
	if type(deserial_func) ~= 'function' then
		panic('input is not a valid Lua expression')
	end
	return deserial_func()
end

setmetatable(pprinter_class, { __index = base_class })
pprinter_class.__inst_mt.__index = pprinter_class

local function static_pprint(val, on_unrepresentable)
	local inst = pprinter_class:new(on_unrepresentable)
	local expr, note = inst:val2expr(val)
	return string.format('%s%s', inst:format_note(note, nil, inst.item_sep), expr)
end

local M = {
	serialize_lua = static_serializer,
	deserialize_lua = deserialize_lua,
	pprint = static_pprint
}

return M
