local kres = require('kres')
local ffi = require('ffi')

local todname = kres.str2dname -- not available during module load otherwise

-- Counter of unique rules
local nextid = 0
local function getruleid()
	local newid = nextid
	nextid = nextid + 1
	return newid
end

-- Support for client sockets from inside policy actions
local socket_client = function () return error("missing luasocket, can't create socket client") end
local has_socket, socket = pcall(require, 'socket')
if has_socket then
	socket_client = function (host, port)
		local s, err, status
		if host:find(':') then
			s, err = socket.udp6()
		else
			s, err = socket.udp()
		end
		if not s then
			return nil, err
		end
		status, err = s:setpeername(host, port)
		if not status then
			return nil, err
		end
		return s
	end
end

local function addr_split_port(target)
	local addr, port = target:match '([^@]*)@?(.*)'
	port = port and tonumber(port) or 53
	return addr, port
end

-- String address@port -> sockaddr.
local function addr2sock(target)
	local addr, port = addr_split_port(target)
	local sock = ffi.gc(ffi.C.kr_straddr_socket(addr, port), ffi.C.free);
	if sock == nil then
		error("target '"..target..'" is not a valid IP address')
	end
	return sock
end

-- Mirror request elsewhere, and continue solving
local function mirror(target)
	local addr, port = addr_split_port(target)
	local sink, err = socket_client(addr, port)
	if not sink then panic('MIRROR target %s is not a valid: %s', target, err) end
	return function(state, req)
		if state == kres.FAIL then return state end
		local query = req.qsource.packet
		if query ~= nil then
			sink:send(ffi.string(query.wire, query.size))
		end
		return -- Chain action to next
	end
end

-- Override the list of nameservers (forwarders)
local function set_nslist(qry, list)
	for i, ns in ipairs(list) do
		assert(ffi.C.kr_nsrep_set(qry, i - 1, ns) == 0);
	end
	-- If less than maximum NSs, insert guard to terminate the list
	if #list < 4 then
		assert(ffi.C.kr_nsrep_set(qry, #list, nil) == 0);
	end
end

-- Forward request, and solve as stub query
local function stub(target)
	local list = {}
	if type(target) == 'table' then
		for _, v in pairs(target) do
			table.insert(list, addr2sock(v))
			assert(#list <= 4, 'at most 4 STUB targets are supported')
		end
	else
		table.insert(list, addr2sock(target))
	end
	return function(state, req)
		local qry = req:current()
		-- Switch mode to stub resolver, do not track origin zone cut since it's not real authority NS
		qry.flags.STUB = true
		qry.flags.ALWAYS_CUT = false
		set_nslist(qry, list)
		return state
	end
end

-- Forward request and all subrequests to upstream; validate answers
local function forward(target)
	local list = {}
	if type(target) == 'table' then
		for _, v in pairs(target) do
			table.insert(list, addr2sock(v))
			assert(#list <= 4, 'at most 4 FORWARD targets are supported')
		end
	else
		table.insert(list, addr2sock(target))
	end
	return function(state, req)
		local qry = req:current()
		req.options.FORWARD = true
		req.options.NO_MINIMIZE = true
		qry.flags.FORWARD = true
		qry.flags.ALWAYS_CUT = false
		qry.flags.NO_MINIMIZE = true
		qry.flags.AWAIT_CUT = true
		set_nslist(qry, list)
		return state
	end
end

-- Forward request and all subrequests to upstream over TCP; validate answers
local function tls_forward(target)
	local sockaddr_list = {}
	local addr_list = {}
	local ca_files = {}
	local hostnames = {}
	local pins = {}
	if type(target) ~= 'table' then
		assert(false, 'wrong TLS_FORWARD target')
	end
	for _, upstream_list_entry in pairs(target) do
		local upstream_addr = upstream_list_entry[1]
		if type(upstream_addr) ~= 'string' then
			assert(false, 'bad IP address in TLS_FORWARD target')
		end
		table.insert(sockaddr_list, addr2sock(upstream_addr))
		table.insert(addr_list, upstream_addr)
		local ca_file = upstream_list_entry['ca_file']
		if ca_file ~= nil then
			local hostname = upstream_list_entry['hostname']
			if hostname == nil then
				assert(false, 'hostname(s) is absent in TLS_FORWARD target')
			end
			ca_files_local = {}
			if type(ca_file) == 'table' then
				for _, v in pairs(ca_file) do
					table.insert(ca_files_local, v)
				end
			else
				table.insert(ca_files_local, ca_file)
			end
			local hostnames_local = {}
			if type(hostname) == 'table' then
				for _, v in pairs(hostname) do
					table.insert(hostnames_local, v)
				end
			else
				table.insert(hostnames_local, hostname)
			end
			if next(ca_files_local) then
				ca_files[upstream_addr] = ca_files_local
			end
			if next(hostnames_local) then
				hostnames[upstream_addr] = hostnames_local
			end
		end
		local pin = upstream_list_entry['pin']
		local pins_local = {}
		if pin ~= nil then
			if type(pin) == 'table' then
				for _, v in pairs(pin) do
					table.insert(pins_local, v)
				end
			else
				table.insert(pins_local, pin)
			end
		end
		if next(pins_local) then
			pins[upstream_addr] = pins_local
		end
	end

	-- Update the global table of authentication data.
	for _, v in pairs(addr_list) do
		if (pins[v] == nil and ca_files[v] == nil) then
			net.tls_client(v)
		elseif (pins[v] ~= nil and ca_files[v] == nil) then
			net.tls_client(v, pins[v])
		elseif (pins[v] == nil and ca_files[v] ~= nil) then
			net.tls_client(v, ca_files[v], hostnames[v])
		else
			net.tls_client(v, pins[v], ca_files[v], hostnames[v])
		end
	end

	return function(state, req)
		local qry = req:current()
		req.options.FORWARD = true
		req.options.NO_MINIMIZE = true
		qry.flags.FORWARD = true
		qry.flags.ALWAYS_CUT = false
		qry.flags.NO_MINIMIZE = true
		qry.flags.AWAIT_CUT = true
		req.options.TCP = true
		qry.flags.TCP = true
		set_nslist(qry, sockaddr_list)
		return state
	end
end

-- Rewrite records in packet
local function reroute(tbl, names)
	-- Import renumbering rules
	local ren = require('renumber')
	local prefixes = {}
	for from, to in pairs(tbl) do
		table.insert(prefixes, names and ren.name(from, to) or ren.prefix(from, to))
	end
	-- Return rule closure
	return ren.rule(prefixes)
end

-- Set and clear some query flags
local function flags(opts_set, opts_clear)
	return function(_, req)
		local qry = req:current()
		ffi.C.kr_qflags_set  (qry.flags, kres.mk_qflags(opts_set   or {}))
		ffi.C.kr_qflags_clear(qry.flags, kres.mk_qflags(opts_clear or {}))
		return nil -- chain rule
	end
end

local function mkauth_soa(answer, dname, mname)
	if mname == nil then
		mname = dname
	end
	return answer:put(dname, 900, answer:qclass(), kres.type.SOA,
		mname .. '\6nobody\7invalid\0\0\0\0\0\0\0\14\16\0\0\3\132\0\9\58\128\0\0\3\132')
end

local dname_localhost = todname('localhost.')

-- Rule for localhost. zone; see RFC6303, sec. 3
local function localhost(_, req)
	local qry = req:current()
	local answer = req.answer
	ffi.C.kr_pkt_make_auth_header(answer)

	local is_exact = ffi.C.knot_dname_is_equal(qry.sname, dname_localhost)

	answer:rcode(kres.rcode.NOERROR)
	answer:begin(kres.section.ANSWER)
	if qry.stype == kres.type.AAAA then
		answer:put(qry.sname, 900, answer:qclass(), kres.type.AAAA,
			'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
	elseif qry.stype == kres.type.A then
		answer:put(qry.sname, 900, answer:qclass(), kres.type.A, '\127\0\0\1')
	elseif is_exact and qry.stype == kres.type.SOA then
		mkauth_soa(answer, dname_localhost)
	elseif is_exact and qry.stype == kres.type.NS then
		answer:put(dname_localhost, 900, answer:qclass(), kres.type.NS, dname_localhost)
	else
		answer:begin(kres.section.AUTHORITY)
		mkauth_soa(answer, dname_localhost)
	end
	return kres.DONE
end

local dname_rev4_localhost = todname('1.0.0.127.in-addr.arpa');
local dname_rev4_localhost_apex = todname('127.in-addr.arpa');

-- Rule for reverse localhost.
-- Answer with locally served minimal 127.in-addr.arpa domain, only having
-- a PTR record in 1.0.0.127.in-addr.arpa, and with 1.0...0.ip6.arpa. zone.
-- TODO: much of this would better be left to the hints module (or coordinated).
local function localhost_reversed(_, req)
	local qry = req:current()
	local answer = req.answer

	-- classify qry.sname:
	local is_exact   -- exact dname for localhost
	local is_apex    -- apex of a locally-served localhost zone
	local is_nonterm -- empty non-terminal name
	if ffi.C.knot_dname_is_sub(qry.sname, todname('ip6.arpa.')) then
		-- exact ::1 query (relying on the calling rule)
		is_exact = true
		is_apex = true
	else
		-- within 127.in-addr.arpa.
		local labels = ffi.C.knot_dname_labels(qry.sname, nil)
		if labels == 3 then
			is_exact = false
			is_apex = true
		elseif labels == 4+2 and ffi.C.knot_dname_is_equal(
					qry.sname, dname_rev4_localhost) then
			is_exact = true
		else
			is_exact = false
			is_apex = false
			is_nonterm = ffi.C.knot_dname_is_sub(dname_rev4_localhost, qry.sname)
		end
	end

	ffi.C.kr_pkt_make_auth_header(answer)
	answer:rcode(kres.rcode.NOERROR)
	answer:begin(kres.section.ANSWER)
	if is_exact and qry.stype == kres.type.PTR then
		answer:put(qry.sname, 900, answer:qclass(), kres.type.PTR, dname_localhost)
	elseif is_apex and qry.stype == kres.type.SOA then
		mkauth_soa(answer, dname_rev4_localhost_apex, dname_localhost)
	elseif is_apex and qry.stype == kres.type.NS then
		answer:put(dname_rev4_localhost_apex, 900, answer:qclass(), kres.type.NS,
			dname_localhost)
	else
		if not is_nonterm then
			answer:rcode(kres.rcode.NXDOMAIN)
		end
		answer:begin(kres.section.AUTHORITY)
		mkauth_soa(answer, dname_rev4_localhost_apex, dname_localhost)
	end
	return kres.DONE
end

local policy = {
	-- Policies
	PASS = 1, DENY = 2, DROP = 3, TC = 4, QTRACE = 5,
	FORWARD = forward, TLS_FORWARD = tls_forward,
	STUB = stub, REROUTE = reroute, MIRROR = mirror, FLAGS = flags,
	-- Special values
	ANY = 0,
}

-- All requests
function policy.all(action)
	return function(_, _) return action end
end

-- Requests which QNAME matches given zone list (i.e. suffix match)
function policy.suffix(action, zone_list)
	local AC = require('ahocorasick')
	local tree = AC.create(zone_list)
	return function(_, query)
		local match = AC.match(tree, query:name(), false)
		if match ~= nil then
			return action
		end
		return nil
	end
end

-- Check for common suffix first, then suffix match (specialized version of suffix match)
function policy.suffix_common(action, suffix_list, common_suffix)
	local common_len = string.len(common_suffix)
	local suffix_count = #suffix_list
	return function(_, query)
		-- Preliminary check
		local qname = query:name()
		if not string.find(qname, common_suffix, -common_len, true) then
			return nil
		end
		-- String match
		for i = 1, suffix_count do
			local zone = suffix_list[i]
			if string.find(qname, zone, -string.len(zone), true) then
				return action
			end
		end
		return nil
	end
end

-- Filter QNAME pattern
function policy.pattern(action, pattern)
	return function(_, query)
		if string.find(query:name(), pattern) then
			return action
		end
		return nil
	end
end

local function rpz_parse(action, path)
	local rules = {}
	local action_map = {
		-- RPZ Policy Actions
		['\0'] = action,
		['\1*\0'] = action, -- deviates from RPZ spec
		['\012rpz-passthru\0'] = policy.PASS, -- the grammar...
		['\008rpz-drop\0'] = policy.DROP,
		['\012rpz-tcp-only\0'] = policy.TC,
		-- Policy triggers @NYI@
	}
	local parser = require('zonefile').new()
	if not parser:open(path) then error(string.format('failed to parse "%s"', path)) end
	while parser:parse() do
		local name = ffi.string(parser.r_owner, parser.r_owner_length)
		local name_action = ffi.string(parser.r_data, parser.r_data_length)
		rules[name] = action_map[name_action]
		-- Warn when NYI
		if #name > 1 and not action_map[name_action] then
			print(string.format('[ rpz ] %s:%d: unsupported policy action', path, tonumber(parser.line_counter)))
		end
	end
	return rules
end

-- Create RPZ from zone file
local function rpz_zonefile(action, path)
	local rules = rpz_parse(action, path)
	collectgarbage()
	return function(_, query)
		local label = query:name()
		local rule = rules[label]
		while rule == nil and string.len(label) > 0 do
			label = string.sub(label, string.byte(label) + 2)
			rule = rules['\1*'..label]
		end
		return rule
	end
end

-- RPZ policy set
function policy.rpz(action, path)
	return rpz_zonefile(action, path)
end

-- Evaluate packet in given rules to determine policy action
function policy.evaluate(rules, req, query, state)
	for i = 1, #rules do
		local rule = rules[i]
		if not rule.suspended then
			local action = rule.cb(req, query)
			if action ~= nil then
				rule.count = rule.count + 1
				local next_state = policy.enforce(state, req, action)
				if next_state then    -- Not a chain rule,
					return next_state -- stop on first match
				end
			end
		end
	end
	return
end

-- Enforce policy action
function policy.enforce(state, req, action)
	if action == policy.DENY then
		-- Write authority information
		local answer = req.answer
		ffi.C.kr_pkt_make_auth_header(answer)
		answer:rcode(kres.rcode.NXDOMAIN)
		answer:begin(kres.section.AUTHORITY)
		mkauth_soa(answer, '\7blocked\0')
		return kres.DONE
	elseif action == policy.DROP then
		return kres.FAIL
	elseif action == policy.TC then
		local answer = req.answer
		if answer.max_size ~= 65535 then
			answer:tc(1) -- ^ Only UDP queries
			return kres.DONE
		end
	elseif action == policy.QTRACE then
		local qry = req:current()
		req.options.TRACE = true
		qry.flags.TRACE = true
		return -- this allows to continue iterating over policy list
	elseif type(action) == 'function' then
		return action(state, req)
	end
	return state
end

-- Top-down policy list walk until we hit a match
-- the caller is responsible for reordering policy list
-- from most specific to least specific.
-- Some rules may be chained, in this case they are evaluated
-- as a dependency chain, e.g. r1,r2,r3 -> r3(r2(r1(state)))
policy.layer = {
	begin = function(state, req)
		req = kres.request_t(req)
		return policy.evaluate(policy.rules, req, req:current(), state) or
		       policy.evaluate(policy.special_names, req, req:current(), state) or
		       state
	end,
	finish = function(state, req)
		req = kres.request_t(req)
		return policy.evaluate(policy.postrules, req, req:current(), state) or state
	end
}

-- Add rule to policy list
function policy.add(rule, postrule)
	-- Compatibility with 1.0.0 API
	-- it will be dropped in 1.2.0
	if rule == policy then
		rule = postrule
		postrule = nil
	end
	-- End of compatibility shim
	local desc = {id=getruleid(), cb=rule, count=0}
	table.insert(postrule and policy.postrules or policy.rules, desc)
	return desc
end

-- Remove rule from a list
local function delrule(rules, id)
	for i, r in ipairs(rules) do
		if r.id == id then
			table.remove(rules, i)
			return true
		end
	end
	return false
end

-- Delete rule from policy list
function policy.del(id)
	if not delrule(policy.rules, id) then
		if not delrule(policy.postrules, id) then
			return false
		end
	end
	return true
end

-- Convert list of string names to domain names
function policy.todnames(names)
	for i, v in ipairs(names) do
		names[i] = kres.str2dname(v)
	end
	return names
end

-- RFC1918 Private, local, broadcast, test and special zones
-- Considerations: RFC6761, sec 6.1.
-- https://www.iana.org/assignments/locally-served-dns-zones
local private_zones = {
	-- RFC6303
	'10.in-addr.arpa.',
	'16.172.in-addr.arpa.',
	'17.172.in-addr.arpa.',
	'18.172.in-addr.arpa.',
	'19.172.in-addr.arpa.',
	'20.172.in-addr.arpa.',
	'21.172.in-addr.arpa.',
	'22.172.in-addr.arpa.',
	'23.172.in-addr.arpa.',
	'24.172.in-addr.arpa.',
	'25.172.in-addr.arpa.',
	'26.172.in-addr.arpa.',
	'27.172.in-addr.arpa.',
	'28.172.in-addr.arpa.',
	'29.172.in-addr.arpa.',
	'30.172.in-addr.arpa.',
	'31.172.in-addr.arpa.',
	'168.192.in-addr.arpa.',
	'0.in-addr.arpa.',
	'254.169.in-addr.arpa.',
	'2.0.192.in-addr.arpa.',
	'100.51.198.in-addr.arpa.',
	'113.0.203.in-addr.arpa.',
	'255.255.255.255.in-addr.arpa.',
	-- RFC7796
	'64.100.in-addr.arpa.',
	'65.100.in-addr.arpa.',
	'66.100.in-addr.arpa.',
	'67.100.in-addr.arpa.',
	'68.100.in-addr.arpa.',
	'69.100.in-addr.arpa.',
	'70.100.in-addr.arpa.',
	'71.100.in-addr.arpa.',
	'72.100.in-addr.arpa.',
	'73.100.in-addr.arpa.',
	'74.100.in-addr.arpa.',
	'75.100.in-addr.arpa.',
	'76.100.in-addr.arpa.',
	'77.100.in-addr.arpa.',
	'78.100.in-addr.arpa.',
	'79.100.in-addr.arpa.',
	'80.100.in-addr.arpa.',
	'81.100.in-addr.arpa.',
	'82.100.in-addr.arpa.',
	'83.100.in-addr.arpa.',
	'84.100.in-addr.arpa.',
	'85.100.in-addr.arpa.',
	'86.100.in-addr.arpa.',
	'87.100.in-addr.arpa.',
	'88.100.in-addr.arpa.',
	'89.100.in-addr.arpa.',
	'90.100.in-addr.arpa.',
	'91.100.in-addr.arpa.',
	'92.100.in-addr.arpa.',
	'93.100.in-addr.arpa.',
	'94.100.in-addr.arpa.',
	'95.100.in-addr.arpa.',
	'96.100.in-addr.arpa.',
	'97.100.in-addr.arpa.',
	'98.100.in-addr.arpa.',
	'99.100.in-addr.arpa.',
	'100.100.in-addr.arpa.',
	'101.100.in-addr.arpa.',
	'102.100.in-addr.arpa.',
	'103.100.in-addr.arpa.',
	'104.100.in-addr.arpa.',
	'105.100.in-addr.arpa.',
	'106.100.in-addr.arpa.',
	'107.100.in-addr.arpa.',
	'108.100.in-addr.arpa.',
	'109.100.in-addr.arpa.',
	'110.100.in-addr.arpa.',
	'111.100.in-addr.arpa.',
	'112.100.in-addr.arpa.',
	'113.100.in-addr.arpa.',
	'114.100.in-addr.arpa.',
	'115.100.in-addr.arpa.',
	'116.100.in-addr.arpa.',
	'117.100.in-addr.arpa.',
	'118.100.in-addr.arpa.',
	'119.100.in-addr.arpa.',
	'120.100.in-addr.arpa.',
	'121.100.in-addr.arpa.',
	'122.100.in-addr.arpa.',
	'123.100.in-addr.arpa.',
	'124.100.in-addr.arpa.',
	'125.100.in-addr.arpa.',
	'126.100.in-addr.arpa.',
	'127.100.in-addr.arpa.',

	-- RFC6303
	-- localhost_reversed handles ::1
	'0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.',
	'd.f.ip6.arpa.',
	'8.e.f.ip6.arpa.',
	'9.e.f.ip6.arpa.',
	'a.e.f.ip6.arpa.',
	'b.e.f.ip6.arpa.',
	'8.b.d.0.1.0.0.2.ip6.arpa.',
}
policy.todnames(private_zones)

-- @var Default rules
policy.rules = {}
policy.postrules = {}
policy.special_names = {
	{
		cb=policy.suffix_common(policy.DENY, private_zones, todname('arpa.')),
		count=0
	},
	{
		cb=policy.suffix(policy.DENY, {
			todname('test.'),
			todname('invalid.'),
			todname('onion.'), -- RFC7686, 2.4
			}),
		count=0
	},
	{
		cb=policy.suffix(localhost, {dname_localhost}),
		count=0
	},
	{
		cb=policy.suffix_common(localhost_reversed, {
			todname('127.in-addr.arpa.'),
			todname('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.')},
			todname('arpa.')),
		count=0
	},
}

return policy
