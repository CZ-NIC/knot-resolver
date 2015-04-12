-- Syntactic sugar for module loading
-- `modules.<name> = <config>`
setmetatable(modules, {
	__newindex = function (t,k,v)
		modules.load(k)
		if _G[k] then
			local config_call = _G[k]['config']
			if config_call and config_call[''] then
				config_call(v)
			end
		end
	end
})

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