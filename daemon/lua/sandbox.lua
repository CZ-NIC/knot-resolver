-- Units
kB = 1024
MB = 1024*1024
GB = 1024*1024
-- Time
sec = 1000
minute = 60 * sec
hour = 60 * minute

-- Function aliases
-- `env.VAR returns os.getenv(VAR)`
env = {}
setmetatable(env, {
	__index = function (t, k) return os.getenv(k) end
})

-- Quick access to interfaces
-- `net.<iface>` => `net.interfaces()[iface]`
setmetatable(net, {
	__index = function (t, k)
		local v = rawget(t, k)
		if v then return v
		else return net.interfaces()[k]
		end
	end
})

-- Syntactic sugar for module loading
-- `modules.<name> = <config>`
setmetatable(modules, {
	__newindex = function (t,k,v)
		if not rawget(_G, k) then
			modules.load(k)
			local mod = rawget(_G, k)
			if mod and mod['config'] then
				mod['config'](v)
			end

		end
	end
})

-- Syntactic sugar for cache
-- `cache.{size|storage} = value`
setmetatable(cache, {
	__newindex = function (t,k,v)
		if     k == 'size'    then t.open(v, rawget(t, 'storage'))
		elseif k == 'storage' then t.open(rawget(t, 'size'), v)
		else   rawset(t, k, v) end
	end
})

-- Register module in Lua environment
function modules_register(module)
	-- Syntactic sugar for get() and set() properties
	setmetatable(module, {
		__index = function (t, k)
			local  v = rawget(t, k)
			if     v     then return v
			elseif rawget(t, 'get') then return t.get(k)
			end
		end,
		__newindex = function (t, k, v)
			local  old_v = rawget(t, k)
			if not old_v and rawget(t, 'set') then
				t.set(k..' '..v)
			end
		end
	})
end

-- Make sandboxed environment
local function make_sandbox(defined)
	local __protected = { modules = true, cache = true, net = true }
	return setmetatable({}, {
		__index = defined,
		__newindex = function (t, k, v)
			if __protected[k] then
				for k2,v2 in pairs(v) do
					defined[k][k2] = v2
				end
			else
				defined[k] = v
			end
		end
	})
end

-- Compatibility sandbox
if setfenv then -- Lua 5.1 and less
	_G = make_sandbox(getfenv(0))
	setfenv(0, _G)
else -- Lua 5.2+
	_SANDBOX = make_sandbox(_ENV)
end

-- Interactive command evaluation
function eval_cmd(line)
	-- Compatibility sandbox code loading
	local function load_code(code)
	    if getfenv then -- Lua 5.1
	        return loadstring(code)
	    else            -- Lua 5.2+
	        return load(code, nil, 't', _ENV)
	    end
	end
	local status, err, chunk
	chunk, err = load_code('table_print('..line..')')
	if err then
		chunk, err = load_code(line)
	end
	if not err then
		chunk()
	end
	if err then
		print(err)
	end
end

-- Pretty printing
function table_print (tt, indent, done)
	done = done or {}
	indent = indent or 0
	if type(tt) == "table" then
		for key, value in pairs (tt) do
			io.write(string.rep (" ", indent))
			if type (value) == "table" and not done [value] then
				done [value] = true
				io.write(string.format("[%s] => {\n", tostring (key)));
				table_print (value, indent + 4, done)
				io.write(string.rep (" ", indent))
				io.write("}\n");
			else
				io.write(string.format("[%s] => %s\n",
				         tostring (key), tostring(value)))
			end
		end
	else
		io.write(tostring(tt) .. "\n")
	end
end