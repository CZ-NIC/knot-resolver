-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface

local ffi = require('ffi')
local basexx = require('basexx')
local C = ffi.C

-- Export module interface
local M = {}
M.layer = {}
local base32 = {}
local str = {}
local AF_INET = 2
local AF_INET6 = 10
local INET_ADDRSTRLEN = 16
local INET6_ADDRSTRLEN = 46

ffi.cdef[[
/*
 * Data structures
 */
typedef int socklen_t;
 struct sockaddr_storage{
		 unsigned short int ss_family;
		 unsigned long int __ss_align;
		 char __ss_padding[128 - (2 *sizeof(unsigned long int))];
 };
 struct in_addr{
		 unsigned char  s_addr[4];
 };
 struct in6_addr{
		 unsigned char s6_addr[16];
 };
 struct sockaddr_in{
		 short sin_family;
		 unsigned short sin_port;
		 struct in_addr sin_addr;
		 char sin_zero[8];
 } __attribute__ ((__packed__));
 struct sockaddr_in6{
		 unsigned short sin6_family;
		 unsigned short sin6_port;
		 unsigned int sin6_flowinfo;
		 struct in6_addr sin6_addr;
		 unsigned int sin6_scope_id;
 };
 typedef unsigned short  sa_family_t;
 struct sockaddr_un {
		 sa_family_t sun_family;
		 char        sun_path[108];
 };
 const char *inet_ntop(
        int af,
        const void *cp,
        char *buf,
        socklen_t len);
]]

function base32.pad(b32)
        local m = #b32 % 8
        if m ~= 0 then
                b32 = b32 .. string.rep("=", 8 - m)
        end
        return b32
end

function str.starts(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

-- Handle DoT signalling NS domains.
function M.layer.consume(state, _, pkt)
	-- Only successful answers
	if state == kres.FAIL then return state end
	-- log("%s", pkt:tostring())
	local authority = pkt:section(kres.section.AUTHORITY)
	local additional = pkt:section(kres.section.ADDITIONAL)
	for _, rr in ipairs(authority) do
		-- log("%d %s", rr.type, kres.dname2str(rr.rdata))
		if rr.type == kres.type.DS then
			-- local content = kres.dname2str(rr.rdata):upper()
			local ds = {}
			ds.owner = rr.owner
			ds.keytag = string.byte(rr.rdata, 1,1) * 256 + string.byte(rr.rdata, 2, 2)
			ds.algo = string.byte(rr.rdata, 3, 3)
			ds.digesttype = string.byte(rr.rdata, 4, 4)
			ds.digest = string.sub(rr.rdata, 5, #rr.rdata)
			-- log('1')
			-- log('type(ds.owner): %s', type(ds.owner))
			-- log('ds.owner: %s', ds.owner)
			log("DS for %s algo %s digesttype %s", kres.dname2str(ds.owner), ds.algo, ds.digesttype)
			-- log('2')
  		if ds.algo == 225 then
  			log('2')
  			-- TODO: we want to add all pins for all IPs, so need to restructure these loops
				for _, rr_add in ipairs(additional) do
					log('2.5, rr_add.type=%s', rr_add.type)
					if rr_add.type == kres.type.A or rr_add.type == kres.type.AAAA then
						log('3')
						log('4')
						log('rr_add.owner=%s', kres.dname2str(rr_add.owner))
						log('5')
	          local addrbuf
						if rr_add.type == kres.type.A then
							log('kres.type.A')
							local ns_addr = ffi.new("struct sockaddr_in")
							ns_addr.sin_family = AF_INET

							ns_addr.sin_addr.s_addr = rr_add.rdata
							addrbuf = ffi.new("char[?]", INET_ADDRSTRLEN)
							C.inet_ntop(AF_INET, ns_addr.sin_addr, addrbuf, INET_ADDRSTRLEN)
						else
							log('kres.type.AAAA')
							local ns_addr = ffi.new("struct sockaddr_in6")
							ns_addr.sin6_family = AF_INET6

							ns_addr.sin6_addr.s6_addr = rr_add.rdata
							addrbuf = ffi.new("char[?]", INET6_ADDRSTRLEN)
							C.inet_ntop(AF_INET6, ns_addr.sin6_addr, addrbuf, INET6_ADDRSTRLEN)
						end
						log("Adding IP %s %s", ffi.string(addrbuf).."@853", basexx.to_base64(ds.digest))
	          net.tls_client(
		          {
	          		ffi.string(addrbuf).."@853",
		          	pin_sha256=basexx.to_base64(ds.digest),
		            hostname=ds.owner
		            -- TODO, two problems:
		            -- the pin turns out to be for any cert in the chain and NOT for the pubkey
		            -- the pseudo DNSKEY prefix needs to be part of the hashed content
		          }
		        )
					end
				end
			end
		end
	end

	return state

end

return M
