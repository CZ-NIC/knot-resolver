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
			eval_cmd(key..'='..'{'..opt..'='..k.value..'}')
		end
	end
end

-- @function reload whole configuration
function ketcd.reload()
	local res, err = ketcd.cli:readdir('/', true)
	if err then
		error(err)
	end
	update_subtree(res.body.node.nodes)	
end

function ketcd.init(module)
	ketcd.Etcd = require('etcd.luasocket')
	ketcd.cli = nil
	ketcd.ev = nil
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
	local cli, err = ketcd.Etcd.new(options)
	if err then
		error(err) 
	end
	ketcd.cli = cli
end

return ketcd
