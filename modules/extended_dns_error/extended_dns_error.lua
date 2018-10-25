-- This module implements Extended DNS Error proposal:
-- https://tools.ietf.org/html/draft-ietf-dnsop-extended-error-02

local kres = require('kres')
local ffi = require('ffi')
local bit = require('bit')
local C = ffi.C

local M = {}

local optcode = 0xFEDE
local max_text_size = 1024

ffi.cdef[[
struct ede_payload {
    uint16_t reserved;
    uint16_t rcode;
    uint16_t icode;
    uint8_t  extra[?];
};
]]

local payload = ffi.new('struct ede_payload', max_text_size)
local payload_ptr = ffi.cast('unsigned char *', payload)
local base_len = ffi.sizeof(payload) - max_text_size

local htons = function(x)
	if not ffi.abi('le') then
		return x
	end
	return bit.rshift(bit.bswap(x), 16)
end

-- module layer hooks
M.layer = {
	finish = function(state, req)
		req = kres.request_t(req)
		local qry = req:last()

		if not qry or qry.err == ffi.C.KR_ERR_OK then
			return state
		end

		-- only enable on DoT/DoH requests
		if not ((req.qsource.tcp and req.qsource.dst_addr:port() == 853) or
			req:vars().request_doh_host) then
			return state
		end


		local pkt = req.answer

		if pkt.opt_rr == nil or
		C.knot_edns_get_option(pkt.opt_rr, optcode) ~= nil then
			return state
		end

		payload.reserved = htons(0)
		payload.rcode = htons(pkt:rcode())
		payload.icode = htons(qry.err)

		-- has not been used yet
		local extra_text = ''
		local n = #extra_text
		if n > 0 then
			if n > max_text_size then
				warn('[ede] data size too large: %d', n)
				return state
			end
			ffi.copy(payload.extra, extra_text)
		end
		local len = base_len + n

		local rc = C.knot_pkt_reserve(pkt, len + 4)
		if rc ~= 0 then
			return state
		end
		C.knot_edns_add_option(pkt.opt_rr, optcode, len, payload_ptr, pkt.mm)
		return state
	end
}

return M
