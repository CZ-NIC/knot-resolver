-- SPDX-License-Identifier: GPL-3.0-or-later

-- LuaJIT ffi bindings for zscanner, a DNS zone parser.
-- Author: Marek Vavrusa <marek.vavrusa@nic.cz>

local ffi = require('ffi')
local libzscanner = ffi.load(libzscanner_SONAME)

-- Wrap scanner context
local zs_scanner_t = ffi.typeof('zs_scanner_t')
ffi.metatype( zs_scanner_t, {
	__gc = function(zs) return libzscanner.zs_deinit(zs) end,
	__new = function(ct, origin, class, ttl)
		if not class then class = 1 end
		if not ttl then ttl = 3600 end
		local parser = ffi.new(ct)
		libzscanner.zs_init(parser, origin, class, ttl)
		return parser
	end,
	__index = {
		open = function (zs, file)
			assert(ffi.istype(zs, zs_scanner_t))
			local ret = libzscanner.zs_set_input_file(zs, file)
			if ret ~= 0 then return false, zs:strerr() end
			return true
		end,
		parse = function(zs, input)
			assert(ffi.istype(zs, zs_scanner_t))
			if input ~= nil then libzscanner.zs_set_input_string(zs, input, #input) end
			local ret = libzscanner.zs_parse_record(zs)
			-- Return current state only when parsed correctly, otherwise return error
			if ret == 0 and zs.state ~= "ZS_STATE_ERROR" then
				return zs.state == "ZS_STATE_DATA"
			else
				return false, zs:strerr()
			end
		end,
		current_rr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return {
				owner = ffi.string(zs.r_owner, zs.r_owner_length),
				ttl = tonumber(zs.r_ttl),
				class = tonumber(zs.r_class),
				type = tonumber(zs.r_type),
				rdata = ffi.string(zs.r_data, zs.r_data_length),
				comment = zs:current_comment(),
			}
		end,
		strerr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return ffi.string(libzscanner.zs_strerror(zs.error.code))
		end,
		current_comment = function(zs)
			if zs.buffer_length > 0 then
				return ffi.string(zs.buffer, zs.buffer_length - 1)
			else
				return nil
			end
		end
	},
})

-- Module API
local rrparser = {
	new = zs_scanner_t,

	-- Parse a file into a list of RRs
	file = function (path)
		local zs = zs_scanner_t()
		local ok, err = zs:open(path)
		if not ok then
			return ok, err
		end
		local results = {}
		while zs:parse() do
			table.insert(results, zs:current_rr())
		end
		return results
	end,

	-- Parse a string into a list of RRs.
	string = function (input)
		local zs = zs_scanner_t()
		local results = {}
		local ok = zs:parse(input)
		while ok do
			table.insert(results, zs:current_rr())
			ok = zs:parse()
		end
		return results
	end,
}
return rrparser
