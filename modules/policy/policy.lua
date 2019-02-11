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

local function addr_split_port(target, default_port)
	assert(default_port)
	assert(type(default_port) == 'number')
	local addr, port = target:match '([^@]*)@?(.*)'
	local nport
	if port ~= "" then
		nport = tonumber(port)
		if not nport or nport < 1 or nport > 65535 then
			error('port "'.. port  ..'" is not valid')
		end
	end
	return addr, nport or default_port
end

-- String address@port -> sockaddr.
local function addr2sock(target, default_port)
	local addr, port = addr_split_port(target, default_port)
	local sock = ffi.gc(ffi.C.kr_straddr_socket(addr, port), ffi.C.free);
	if sock == nil then
		error("target '"..target..'" is not a valid IP address')
	end
	return sock
end

-- policy functions are defined below
local policy = {}

function policy.PASS(state, _)
	return state
end

-- Mirror request elsewhere, and continue solving
function policy.MIRROR(target)
	local addr, port = addr_split_port(target, 53)
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
	local ns_i = 0
	for _, ns in ipairs(list) do
		-- kr_nsrep_set() can return kr_error(ENOENT), it's OK
		if ffi.C.kr_nsrep_set(qry, ns_i, ns) == 0 then
			ns_i = ns_i + 1
		end
	end
	-- If less than maximum NSs, insert guard to terminate the list
	if ns_i < 3 then
		assert(ffi.C.kr_nsrep_set(qry, ns_i, nil) == 0);
	end
	if ns_i == 0 then
		-- would use assert() but don't want to compose the message if not triggered
		error('no usable address in NS set (check net.ipv4 and '
		      .. 'net.ipv6 config):\n' .. table_print(list, 2))
	end
end

-- Forward request, and solve as stub query
function policy.STUB(target)
	local list = {}
	if type(target) == 'table' then
		for _, v in pairs(target) do
			table.insert(list, addr2sock(v, 53))
			assert(#list <= 4, 'at most 4 STUB targets are supported')
		end
	else
		table.insert(list, addr2sock(target, 53))
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
function policy.FORWARD(target)
	local list = {}
	if type(target) == 'table' then
		for _, v in pairs(target) do
			table.insert(list, addr2sock(v, 53))
			assert(#list <= 4, 'at most 4 FORWARD targets are supported')
		end
	else
		table.insert(list, addr2sock(target, 53))
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

-- object must be non-empty string or non-empty table of non-empty strings
local function is_nonempty_string_or_table(object)
	if type(object) == 'string' then
		return #object ~= 0
	elseif type(object) ~= 'table' or not next(object) then
		return false
	end
	for _, val in pairs(object) do
		if type(val) ~= 'string' or #val == 0 then
			return false
		end
	end
	return true
end

local function insert_from_string_or_table(source, destination)
	if type(source) == 'table' then
		for _, v in pairs(source) do
			table.insert(destination, v)
		end
	else
		table.insert(destination, source)
	end
end

-- Check for allowed authentication types and return type for the current target
local function tls_forward_target_authtype(idx, target)
	if (target.pin_sha256 and not (target.ca_file or target.hostname or target.insecure)) then
		if not is_nonempty_string_or_table(target.pin_sha256) then
			error('TLS_FORWARD target authentication is invalid at position '
			      .. idx .. '; pin_sha256 must be string or list of strings')
		end
		return 'pin_sha256'
	elseif (target.insecure and not (target.ca_file or target.hostname or target.pin_sha256)) then
		return 'insecure'
	elseif (target.hostname and not (target.insecure or target.pin_sha256)) then
		if not (is_nonempty_string_or_table(target.hostname)) then
			error('TLS_FORWARD target authentication is invalid at position '
			      .. idx .. '; hostname must be string or list of strings')
		end
		-- if target.ca_file is empty, system CA will be used
		return 'cert'
	else
		error('TLS_FORWARD authentication options at position ' .. idx
		      .. ' are invalid; specify one of: pin_sha256 / hostname [+ca_file] / insecure')
	end
end

local function tls_forward_target_check_syntax(idx, list_entry)
	if type(list_entry) ~= 'table' then
		error('TLS_FORWARD target must be a non-empty table (found '
		      .. type(list_entry) .. ' at position ' .. idx .. ')')
	end
	if type(list_entry[1]) ~= 'string' then
		error('TLS_FORWARD target must start with an IP address (found '
		      .. type(list_entry[1]) .. ' at the beginning of target position ' .. idx .. ')')
	end
end

-- Forward request and all subrequests to upstream over TLS; validate answers
function policy.TLS_FORWARD(target)
	local sockaddr_c_list = {}
	local sockaddr_config = {}  -- items: { string_addr=<addr string>, auth_type=<auth type> }
	local ca_files = {}
	local hostnames = {}
	local pins = {}
	if type(target) ~= 'table' or #target < 1 then
		error('TLS_FORWARD argument must be a non-empty table')
	end
	for idx, upstream_list_entry in pairs(target) do
		tls_forward_target_check_syntax(idx, upstream_list_entry)
		local auth_type = tls_forward_target_authtype(idx, upstream_list_entry)
		local string_addr = upstream_list_entry[1]
		local sockaddr_c = addr2sock(string_addr, 853)
		local sockaddr_lua = ffi.string(sockaddr_c, ffi.C.kr_sockaddr_len(sockaddr_c))
		if sockaddr_config[sockaddr_lua] then
			error('TLS_FORWARD configuration cannot declare two configs for IP address ' .. string_addr)
		end
		table.insert(sockaddr_c_list, sockaddr_c)
		sockaddr_config[sockaddr_lua] = {string_addr=string_addr, auth_type=auth_type}
		if auth_type == 'cert' then
			ca_files[sockaddr_lua] = {}
			hostnames[sockaddr_lua] = {}
			insert_from_string_or_table(upstream_list_entry.ca_file, ca_files[sockaddr_lua])
			insert_from_string_or_table(upstream_list_entry.hostname, hostnames[sockaddr_lua])
		elseif auth_type == 'pin_sha256' then
			pins[sockaddr_lua] = {}
			insert_from_string_or_table(upstream_list_entry.pin_sha256, pins[sockaddr_lua])
		elseif auth_type ~= 'insecure' then
			-- insecure does nothing, user does not want authentication
			assert(false, 'unsupported auth_type')
		end
	end

	-- Update the global table of authentication data only if all checks above passed
	for sockaddr_lua, config in pairs(sockaddr_config) do
		assert(#config.string_addr > 0)
		if config.auth_type == 'insecure' then
			net.tls_client(config.string_addr)
		elseif config.auth_type == 'pin_sha256' then
			assert(#pins[sockaddr_lua] > 0)
			net.tls_client(config.string_addr, pins[sockaddr_lua])
		elseif config.auth_type == 'cert' then
			assert(#hostnames[sockaddr_lua] > 0)
			net.tls_client(config.string_addr, ca_files[sockaddr_lua], hostnames[sockaddr_lua])
		else
			assert(false, 'unsupported auth_type')
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
		set_nslist(qry, sockaddr_c_list)
		return state
	end
end

-- Rewrite records in packet
function policy.REROUTE(tbl, names)
	-- Import renumbering rules
	local ren = require('kres_modules.renumber')
	local prefixes = {}
	for from, to in pairs(tbl) do
		table.insert(prefixes, names and ren.name(from, to) or ren.prefix(from, to))
	end
	-- Return rule closure
	return ren.rule(prefixes)
end

-- Set and clear some query flags
function policy.FLAGS(opts_set, opts_clear)
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
	return answer:put(dname, 10800, answer:qclass(), kres.type.SOA,
		mname .. '\6nobody\7invalid\0\0\0\0\1\0\0\14\16\0\0\4\176\0\9\58\128\0\0\42\48')
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
	if ffi.C.knot_dname_in_bailiwick(qry.sname, todname('ip6.arpa.')) > 0 then
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
			is_nonterm = ffi.C.knot_dname_in_bailiwick(dname_rev4_localhost, qry.sname) > 0
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

-- All requests
function policy.all(action)
	return function(_, _) return action end
end

-- Requests which QNAME matches given zone list (i.e. suffix match)
function policy.suffix(action, zone_list)
	local AC = require('kres_modules.ahocorasick')
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
			log('[poli] RPZ %s:%d: unsupported policy action', path, tonumber(parser.line_counter))
		end
	end
	collectgarbage()
	return rules
end

-- Split path into dirname and basename (like the shell utilities)
local function get_dir_and_file(path)
	local dir, file = string.match(path, "(.*)/([^/]+)")

	-- If regex doesn't match then path must be the file directly (i.e. doesn't contain '/')
	-- This assumes that the file exists (rpz_parse() would fail if it doesn't)
	if not dir and not file then
		dir = '.'
		file = path
	end

	return dir, file
end

-- RPZ policy set
-- Create RPZ from zone file and optionally watch the file for changes
function policy.rpz(action, path, watch)
	local rules = rpz_parse(action, path)

	if watch or true then
		local has_notify, notify  = pcall(require, 'cqueues.notify')
		if has_notify then
			local bit = require('bit')

			local dir, file = get_dir_and_file(path)
			local watcher = notify.opendir(dir)
			watcher:add(file, bit.bxor(notify.CREATE, notify.MODIFY))

			worker.coroutine(function ()
				for _, name in watcher:changes() do
					-- Limit to changes on file we're interested in
					-- Watcher will also fire for changes to the directory itself
					if name == file then
						-- If the file changes then reparse and replace the existing ruleset
						if verbose() then
							log('[poli] RPZ reloading: ' .. name)
						end
						rules = rpz_parse(action, path)
					end
				end
			end)
		elseif watch then -- explicitly requested and failed
			error('[poli] lua-cqueues required to watch and reload RPZ file')
		elseif verbose() then
			log('[poli] lua-cqueues required to watch and reload RPZ file, continuing without watching')
		end
	end

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

function policy.DENY_MSG(msg)
	if msg and (type(msg) ~= 'string' or #msg >= 255) then
		error('DENY_MSG: optional msg must be string shorter than 256 characters')
        end

	return function (_, req)
		-- Write authority information
		local answer = req.answer
		ffi.C.kr_pkt_make_auth_header(answer)
		answer:rcode(kres.rcode.NXDOMAIN)
		answer:begin(kres.section.AUTHORITY)
		mkauth_soa(answer, answer:qname())
		if msg then
			answer:begin(kres.section.ADDITIONAL)
			answer:put('\11explanation\7invalid', 10800, answer:qclass(), kres.type.TXT,
				   string.char(#msg) .. msg)

		end
		return kres.DONE
	end
end
policy.DENY = policy.DENY_MSG() -- compatibility with < 2.0

function policy.DROP(_, _)
	return kres.FAIL
end

function policy.REFUSE(_, req)
	local answer = req.answer
	answer:rcode(kres.rcode.REFUSED)
	answer:ad(false)
	return kres.DONE
end

function policy.TC(state, req)
	local answer = req.answer
	if answer.max_size ~= 65535 then
		answer:tc(1) -- ^ Only UDP queries
		answer:ad(false)
		return kres.DONE
	else
		return state
	end
end

function policy.QTRACE(_, req)
	local qry = req:current()
	req.options.TRACE = true
	qry.flags.TRACE = true
	return -- this allows to continue iterating over policy list
end

-- Evaluate packet in given rules to determine policy action
function policy.evaluate(rules, req, query, state)
	for i = 1, #rules do
		local rule = rules[i]
		if not rule.suspended then
			local action = rule.cb(req, query)
			if action ~= nil then
				rule.count = rule.count + 1
				local next_state = action(state, req)
				if next_state then    -- Not a chain rule,
					return next_state -- stop on first match
				end
			end
		end
	end
	return
end

-- Top-down policy list walk until we hit a match
-- the caller is responsible for reordering policy list
-- from most specific to least specific.
-- Some rules may be chained, in this case they are evaluated
-- as a dependency chain, e.g. r1,r2,r3 -> r3(r2(r1(state)))
policy.layer = {
	begin = function(state, req)
		-- Don't act on "resolved" cases.
		if bit.band(state, bit.bor(kres.FAIL, kres.DONE)) ~= 0 then return state end

		req = kres.request_t(req)
		return policy.evaluate(policy.rules, req, req:current(), state) or
		       policy.evaluate(policy.special_names, req, req:current(), state) or
		       state
	end,
	finish = function(state, req)
		-- Don't act on "resolved" cases.
		if bit.band(state, bit.bor(kres.FAIL, kres.DONE)) ~= 0 then return state end

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
	-- RFC7793
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
		cb=policy.suffix_common(policy.DENY_MSG(
			'Blocking is mandated by standards, see references on '
			.. 'https://www.iana.org/assignments/'
			.. 'locally-served-dns-zones/locally-served-dns-zones.xhtml'),
			private_zones, todname('arpa.')),
		count=0
	},
	{
		cb=policy.suffix(policy.DENY_MSG(
			'Blocking is mandated by standards, see references on '
			.. 'https://www.iana.org/assignments/'
			.. 'special-use-domain-names/special-use-domain-names.xhtml'),
			{
				todname('test.'),
				todname('onion.'),
				todname('invalid.'),
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
