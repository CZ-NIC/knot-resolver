--- @module ketcd
local ketcd = {}

-- @function update subtree configuration
local function update_subtree(tree)
	if not tree then return end
	for i,k in pairs(tree) do
		if k.dir then
			update_subtree(k.nodes)
		else
			local key,opt = k.key:gmatch('([^/]+)/([^/]+)$')()
			if _G[key][opt] ~= k.value then
				_G[key][opt] = k.value
			end
		end
	end
end

-- @function reload whole configuration
function ketcd.reload()
	local ketcd = _G['ketcd']
	local res, err = ketcd.cli:readdir('/', true)
	if err then
		error(err)
	end
	update_subtree(res.body.node.nodes)	
end

function ketcd.init(module)
	ketcd.Etcd = require('etcd.luasocket')
	ketcd.defaults = { prefix = '/kresolved' }
end

function ketcd.deinit(module)
	if ketcd.ev then event.cancel(ketcd.ev) end
end

function ketcd.config(conf)
	local options = ketcd.defaults
	if type(conf) == 'table' then
		for k,v in pairs(conf) do options[k] = v end
	end
	-- create connection
	local cli, err = ketcd.Etcd.new(options)
	if err then
		error(err) 
	end
	ketcd.cli = cli
	-- schedule recurrent polling
	-- @todo: the etcd has watch() API, but this requires
	--        coroutines on socket operations
	if ketcd.ev then event.cancel(ketcd.ev) end
	ketcd.ev = event.recurrent(5 * sec, ketcd.reload)
end

return ketcd
