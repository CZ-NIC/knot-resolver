-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')
local kr_cach = kres.context().cache


local charset = {
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-'}

local function gen_bytes(len)
	local bytes = {}
	for _ = 1,len do
		table.insert(bytes, charset[math.random(1, #charset)])
	end
	local result = table.concat(bytes)
	assert(#result == len)
	return result
end

local function gen_ttl()
	return math.random(0, 2^31-1)
end

local function gen_rrtype()
	return math.random(1024, 61000)
end

local function gen_rdata(len)
	assert(len >= 1 and len <= 65535)
	return gen_bytes(len)
end

local function gen_label(len)  -- in bytes including the length byte
	assert(len >= 2 and len <= 64)
	local bytes = {string.char(len - 1), gen_bytes(len - 1)}
	return table.concat(bytes)
end

local function gen_dname()
	local target_len  -- length 2 bytes does not make sense
	while target_len == nil or target_len == 2 do
		target_len = math.random(1, 255)
	end

	local labels = {string.char(0)}
	local cur_len = 1
	while target_len > cur_len do
		local new_len = math.random(
					2,
					math.min(target_len - cur_len,
						64))
		if (target_len - cur_len - new_len) == 1 then
			-- it is a trap, single-byte label is allowed only at the end
			-- we cannot leave room for single-byte label in the next round
			if new_len == 64 then
				goto continue  -- we are at max label length, try again
			end
			new_len = new_len + 1
		end
		table.insert(labels, 1, gen_label(new_len))
		cur_len = cur_len + new_len
		::continue::
	end
	assert(target_len == cur_len)
	local dname = table.concat(labels)
	assert(#dname >= 1 and #dname <= 255)
	assert(string.byte(dname, #dname) == 0)
	return dname
end


local function gen_rrset()
	local rrs = {}
	local maxsize = 300  -- RR data size in bytes per RR set, does not include owner etc.
	local target_len = math.random(1, maxsize)
	local cur_len = 0
	while target_len > cur_len do
		local new_len = math.random(1, target_len - cur_len)
		local new_rr = gen_rdata(new_len)
		cur_len = cur_len + #new_rr
		table.insert(rrs, new_rr)
	end
	assert(target_len == cur_len)
	return rrs, cur_len
end


local function add_random_rrset()
	local owner = gen_dname()
	local ttl = gen_ttl()
	local rr_type = gen_rrtype()
	local rdata_set = gen_rrset()

	local kr_rrset = kres.rrset(owner, rr_type, kres.class.IN, ttl)
	for _, rr in ipairs(rdata_set) do
		assert(kr_rrset:add_rdata(rr, #rr))
	end
	assert(kr_cach:insert(kr_rrset, nil, ffi.C.KR_RANK_SECURE))
end

ffi.cdef('int usleep(uint32_t usec);') -- at least in current glibc it's always 32-bit

local rr_count = 0
local function gen_batch()
	for _ = 1,math.random(1,10) do
		add_random_rrset()
		rr_count = rr_count + 1
		if rr_count % 100 == 0 then
			print('cache usage ', cache.stats()['usage_percent'], '%')
		end
	end
	kr_cach:commit()
	ffi.C.usleep(15) -- stop *whole process* to give better chance to GC executing
	local delay
	if math.random(1,4) == 1 then
		delay = 1  -- give a chance to DNS resolving
	else
		delay = 0
	end
	event.after(delay, gen_batch)
end

return {
	add_random_rrset=add_random_rrset,
	gen_batch=gen_batch,
	gen_bytes=gen_bytes,
	gen_dname=gen_dname,
	gen_label=gen_label,
	gen_rdata=gen_rdata,
	gen_rrset=gen_rrset,
	gen_rrtype=gen_rrtype,
	gen_ttl=gen_ttl
}
