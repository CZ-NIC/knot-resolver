-- Syntactic sugar for module loading
-- `modules.<name> = <config>`
local modules_mt = {
	__newindex = function (t,k,v)
		modules.load(k)
		_G[k]['config'](v)
	end
}
setmetatable(modules, modules_mt)