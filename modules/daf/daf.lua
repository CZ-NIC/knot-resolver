local cqueues = require('cqueues')

-- Module declaration
local M = {
}

-- @function Public-facing API
local function api(h, stream)
	print('DAF: ')
	for k,v in h:each() do print(k,v) end
end

-- @function Publish DAF statistics
local function publish(h, ws)
	local ok = true
	while ok do
		-- Publish stats updates periodically
		local push = tojson({})
		ok = ws:send(push)
		cqueues.sleep(0.5)
	end
	ws:close()
end

-- @function Cleanup module
function M.deinit()
	if http then
		http.endpoints['/daf'] = nil
		http.snippets['/daf'] = nil
	end
end

-- @function Configure module
function M.config(conf)
	if not http then error('"http" module is not loaded, cannot load DAF') end
	-- Export API and data publisher
	http.endpoints['/daf'] = {'application/json', api, publish}
	-- Export snippet
	http.snippets['/daf'] = {'Application Firewall', [[
		<p>Hello world!</p>
	]]}
end

return M