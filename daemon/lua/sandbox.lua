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
function make_sandbox(defined)
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

if setfenv then -- Lua 5.1 and less
	_G = make_sandbox(getfenv(0))
	setfenv(0, _G)
else -- Lua 5.2+
	_SANDBOX = make_sandbox(_ENV)
end
