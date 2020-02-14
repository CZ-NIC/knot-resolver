--- @module etcd
-- SPDX-License-Identifier: GPL-3.0-or-later
local etcd = {}

-- @function update subtree configuration
local function update_subtree(tree)
	if not tree then return end
	for _, k in pairs(tree) do
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
function etcd.reload()
	local res, err = etcd.cli:readdir('/', true)
	if err then
		error(err)
	end
	update_subtree(res.body.node.nodes)
end

function etcd.init()
	etcd.Etcd = require('etcd.luasocket')
	etcd.defaults = { prefix = '/knot-resolver' }
end

function etcd.deinit()
	if etcd.ev then event.cancel(etcd.ev) end
end

function etcd.config(conf)
	local options = etcd.defaults
	if type(conf) == 'table' then
		for k,v in pairs(conf) do options[k] = v end
	end
	-- create connection
	local cli, err = etcd.Etcd.new(options)
	if err then
		error(err)
	end
	etcd.cli = cli
	-- schedule recurrent polling
	-- @todo: the etcd has watch() API, but this requires
	--        coroutines on socket operations
	if etcd.ev then event.cancel(etcd.ev) end
	etcd.ev = event.recurrent(5 * sec, etcd.reload)
end

return etcd
