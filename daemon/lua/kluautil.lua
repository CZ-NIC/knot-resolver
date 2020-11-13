-- SPDX-License-Identifier: GPL-3.0-or-later

local ffi = require('ffi')
local kluautil = {}

-- Get length of table
function kluautil.kr_table_len(t)
	if type(t) ~= 'table' then
		return nil
	end

	local len = 0
	for _ in pairs(t) do
		len = len + 1
	end
	return len
end

-- pack varargs including nil arguments into a table
function kluautil.kr_table_pack(...)
	local tab = {...}
	tab.n = select('#', ...)
	return tab
end

-- unpack table produced by kr_table_pack and including nil values
function kluautil.kr_table_unpack(tab)
	return unpack(tab, 1, tab.n)
end

-- Fetch over HTTPS
function kluautil.kr_https_fetch(url, out_file, ca_file)
	local http_ok, http_request = pcall(require, 'http.request')
	local httptls_ok, http_tls = pcall(require, 'http.tls')
	local openssl_ok, openssl_ctx = pcall(require, 'openssl.ssl.context')

	if not http_ok or not httptls_ok or not openssl_ok then
		return nil, 'error: lua-http and luaossl libraries are missing (but required)'
	end
	local cqerrno = require('cqueues.errno')

	assert(string.match(url, '^https://'))

	local req = http_request.new_from_uri(url)
	req.tls = true
	if ca_file then
		req.ctx = openssl_ctx.new()
		local store = req.ctx:getStore()
		local load_ok, errmsg = pcall(store.add, store, ca_file)
		if not load_ok then
			return nil, errmsg
		end
	else  -- use defaults
		req.ctx = http_tls.new_client_context()
	end

	req.ctx:setVerify(openssl_ctx.VERIFY_PEER)

	local headers, stream, errmsg = req:go()
	if not headers then
		errmsg = errmsg or 'unknown error'
		if type(errmsg) == 'number' then
			errmsg = cqerrno.strerror(errmsg) ..
				' (' .. tostring(errmsg) .. ')'
		end
		return nil, 'HTTP client library error: ' .. errmsg
	end
	if headers:get(':status') ~= "200" then
		return nil, 'HTTP status != 200, got ' .. headers:get(':status')
	end

	local err
	err, errmsg = stream:save_body_to_file(out_file)
	if err == nil then
		return nil, errmsg
	end

	out_file:seek('set', 0)

	return true
end

kluautil.list_dir = kluautil_list_dir

return kluautil
