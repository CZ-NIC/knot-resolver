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

-- Some services are append-only
function protect(defined)
	local __protected = { ['modules'] = true }
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
-- _G = protect(getfenv(0))
-- setfenv(0, _G)
