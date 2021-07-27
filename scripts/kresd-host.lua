#!/usr/bin/env luajit
-- SPDX-License-Identifier: GPL-3.0-or-later
-- Work around OS X stripping dyld variables
cli_bin = 'luajit scripts/kresd-query.lua'
libdir = os.getenv('DYLD_LIBRARY_PATH')
if libdir then
	cli_bin = string.format('DYLD_LIBRARY_PATH="%s" %s', libdir, cli_bin)
end
-- Parse CLI arguments
local function help(rc)
	print(string.format([[
Usage: %s [-vdh46D] [-c class] [-t type]
          [-f keyfile] hostname
  Queries the DNS for information.
  The hostname is looked up for IP4, IP6 and mail.
  Use the -v option to see DNSSEC security information.
    -t type     what type to look for.
    -c class    what class to look for, if not class IN.
    -C confstr  additional kresd-style configuration.
    -D          DNSSEC enable with default root anchor
    -f keyfile  read trust anchors from file, with lines as -y.
    -v          be more verbose, shows nodata and security.
    -d          debug, traces the action, -d -d shows more.
    -4          use ipv4 network, avoid ipv6.
    -6          use ipv6 network, avoid ipv4.
    -h          show this usage help.]],
    arg[0]))
	return rc
end

-- Parse CLI arguments
if #arg < 1 then
	return help(1)
end
local qtypes, qclass, qname = {}, 'IN', nil
local verbose, config = false, {}
k = 1 while k <= #arg do
	local v = arg[k]
	if v == '-h' or v == '--help' then
		return help(0)
	elseif v == '-C' then
		k = k + 1
		table.insert(config, arg[k])
	elseif v == '-D' then
		table.insert(config, 'trust_anchors.add_file("root.keys")')
	elseif v == '-f' then
		k = k + 1
		table.insert(config, string.format('trust_anchors.add_file("%s")', arg[k]))
	elseif v == '-v' then
		verbose = true
	elseif v == '-d' then
		verbose = true
		table.insert(config, 'log_level("debug")')
	elseif v == '-4' then
		table.insert(config, 'net.ipv6 = false')
	elseif v == '-6' then
		table.insert(config, 'net.ipv4 = false')
	elseif v == '-c' then
		k = k + 1
		qclass = arg[k]:upper()
	elseif v == '-t' then
		k = k + 1
		table.insert(qtypes, arg[k]:upper())
	elseif v:byte() == string.byte('-') then
		return help(1)
	else
		qname = v
		-- Check if name is an IP addresses
		-- @TODO: convert to domain name and make a PTR lookup
	end
	k = k + 1
end
if not qname then
	return help(1)
end
if #qtypes == 0 then
	qtypes = {'A', 'AAAA', 'MX'}
end
-- Assemble config/query
for _, qtype in ipairs(qtypes) do
	query = string.format('-t %s -c %s %s', qtype, qclass, qname)
	capture = string.format([[
	local qname = "%s"
	local qtype = "%s"
	local qverbose = %s]], qname, qtype, tostring(verbose))..[[
	local qry = req:resolved()
	local section = pkt:rrsets(kres.section.ANSWER)
	for i = 1, #section do
		local rr = section[i]
		for k = 1, rr.rrs.count do
			local rdata = rr:tostring(k - 1)
			local owner = kres.dname2str(rr:owner())
			if qverbose then
				if not qry.flags.DNSSEC_WANT or qry.flags.DNSSEC_INSECURE then
						rdata = rdata .. " (insecure)"
				else
						rdata = rdata .. " (secure)"
				end
			end
			if rr.type == kres.type.A then
				print(string.format("%s has address %s", owner, rdata))
			elseif rr.type == kres.type.AAAA then
				print(string.format("%s has IPv6 address %s", owner, rdata))
			elseif rr.type == kres.type.MX then
				print(string.format("%s mail is handled by %s", owner, rdata))
			elseif rr.type == kres.type.CNAME then
				print(string.format("%s is an alias for %s", owner, rdata))
			else
				print(string.format("%s has %s record %s", owner, qtype, rdata))
			end
		end
	end
	]]
	os.execute(string.format('%s -C \'%s\' %s \'%s\'', cli_bin, table.concat(config, ' '), query, capture))
end
