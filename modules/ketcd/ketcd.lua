--- @module ketcd
local ketcd = {}
local Etcd = require('etcd.luasocket')

function ketcd.init(module)
	print('wip')
end

function ketcd.deinit(module)
	print('wip')
end

function ketcd.config(module, conf)
	local cli, err = Etcd.new({
		peer = conf,
	});	
	ketcd._cli = cli
end

function ketcd.layers(module)
	return {}
end

return ketcd
