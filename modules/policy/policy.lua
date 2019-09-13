-- SPDX-License-Identifier: GPL-3.0-or-later
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
local socket_client = function ()
	return error("missing lua-cqueues library, can't create socket client")
end
local has_socket, socket = pcall(require, 'cqueues.socket')
if has_socket then
	socket_client = function (host, port)
		local s, err, status

		s = socket.connect({ host = host, port = port, type = socket.SOCK_DGRAM })
		s:setmode('bn', 'bn')
		status, err = pcall(s.connect, s)

		if not status then
			return status, err
		end
		return s
	end
end

-- Split address and port from a combined string.
local function addr_split_port(target, default_port)
	assert(default_port and type(default_port) == 'number')
	local port = ffi.new('uint16_t[1]', default_port)
	local addr = ffi.new('char[47]') -- INET6_ADDRSTRLEN + 1
	local ret = ffi.C.kr_straddr_split(target, addr, port)
	if ret ~= 0 then
		error('failed to parse address ' .. target)
	end
	return addr, tonumber(port[0])
end

-- String address@port -> sockaddr.
local function addr2sock(target, default_port)
	local addr, port = addr_split_port(target, default_port)
	local sock = ffi.gc(ffi.C.kr_straddr_socket(addr, port, nil), ffi.C.free);
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
	local sink, err = socket_client(ffi.string(addr), port)
	if not sink then panic('MIRROR target %s is not a valid: %s', target, err) end
	return function(state, req)
		if state == kres.FAIL then return state end
		local query = req.qsource.packet
		if query ~= nil then
			sink:send(ffi.string(query.wire, query.size), 1, tonumber(query.size))
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

-- Forward request and all subrequests to upstream over TLS; validate answers
function policy.TLS_FORWARD(targets)
	if type(targets) ~= 'table' or #targets < 1 then
		error('TLS_FORWARD argument must be a non-empty table')
	elseif #targets > 4 then
		error('TLS_FORWARD supports at most four targets (in a single call)')
	end

	local sockaddr_c_set = {}
	local nslist = {} -- to persist in closure of the returned function
	for idx, target in pairs(targets) do
		if type(target) ~= 'table' or type(target[1]) ~= 'string' then
			error(string.format('TLS_FORWARD configuration at position ' ..
			'%d must be a table starting with an IP address', idx))
		end
		-- Note: some functions have checks with error() calls inside.
		local sockaddr_c = addr2sock(target[1], 853)

		-- Refuse repeated addresses in the same set.
		local sockaddr_lua = ffi.string(sockaddr_c, ffi.C.kr_sockaddr_len(sockaddr_c))
		if sockaddr_c_set[sockaddr_lua] then
			error('TLS_FORWARD configuration cannot declare two configs for IP address '
					.. target[1])
		else
			sockaddr_c_set[sockaddr_lua] = true;
		end

		table.insert(nslist, sockaddr_c)
		net.tls_client(target)
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
		set_nslist(qry, nslist)
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

-- Create answer with passed arguments
function policy.ANSWER(rtable, nodata)
	return function(_, req)
		local qry = req:current()
		local answer = req:ensure_answer()
		local data = rtable[qry.stype]

		ffi.C.kr_pkt_make_auth_header(answer)

		if data == nil then
			if nodata == true then
				answer:rcode(kres.rcode.NOERROR)
				return kres.DONE
			end
		else
			local ttl = data.ttl or 1

			answer:rcode(kres.rcode.NOERROR)
			answer:begin(kres.section.ANSWER)
			if type(data.rdata) == 'table' then
				for _, rdato in ipairs(data.rdata) do
					answer:put(qry.sname, ttl, qry.sclass, qry.stype, rdato)
				end
			else
				answer:put(qry.sname, ttl, qry.sclass, qry.stype, data.rdata)
			end

			return kres.DONE
		end
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
	local answer = req:ensure_answer()
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
	local answer = req:ensure_answer()

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
	local new_actions = {}
	local action_map = {
		-- RPZ Policy Actions
		['\0'] = action,
		['\1*\0'] = policy.ANSWER({}, true),
		['\012rpz-passthru\0'] = policy.PASS, -- the grammar...
		['\008rpz-drop\0'] = policy.DROP,
		['\012rpz-tcp-only\0'] = policy.TC,
		-- Policy triggers @NYI@
	}
	-- RR types to be skipped; boolean denoting whether to throw a warning even for RPZ apex.
	local rrtype_bad = {
		[kres.type.DNAME]  = true,
		[kres.type.NS]     = false,
		[kres.type.SOA]    = false,
		[kres.type.DNSKEY] = true,
		[kres.type.DS]     = true,
		[kres.type.RRSIG]  = true,
		[kres.type.NSEC]   = true,
		[kres.type.NSEC3]  = true,
	}
	local parser = require('zonefile').new()
	local ok, errstr = parser:open(path)
	if not ok then
		error(string.format('failed to parse "%s": %s', path, errstr or "unknown error"))
	end
	while true do
		ok, errstr = parser:parse()
		if errstr then
			log('[poli] RPZ %s:%d: %s', path, tonumber(parser.line_counter), errstr)
		end
		if not ok then break end

		local full_name = ffi.gc(ffi.C.knot_dname_copy(parser.r_owner, nil), ffi.C.free)
		local rdata = ffi.string(parser.r_data, parser.r_data_length)
		ffi.C.knot_dname_to_lower(full_name)

		local prefix_labels = ffi.C.knot_dname_in_bailiwick(full_name, parser.zone_origin)
		if prefix_labels < 0 then
			log('[poli] RPZ %s:%d: RR owner "%s" outside the zone (ignored)',
				path, tonumber(parser.line_counter), kres.dname2str(full_name))
			goto continue
		end

		local bytes = ffi.C.knot_dname_size(full_name) - ffi.C.knot_dname_size(parser.zone_origin)
		local name = ffi.string(full_name, bytes) .. '\0'

		if parser.r_type == kres.type.CNAME then
			if action_map[rdata] then
				rules[name] = action_map[rdata]
			else
				log('[poli] RPZ %s:%d: CNAME with custom target in RPZ is not supported yet (ignored)',
					path, tonumber(parser.line_counter))
			end
		else
			if #name then
				local is_bad = rrtype_bad[parser.r_type]
				if is_bad == true or (is_bad == false and prefix_labels ~= 0) then
					log('[poli] RPZ %s:%d warning: RR type %s is not allowed in RPZ (ignored)',
						path, tonumber(parser.line_counter), kres.tostring.type[parser.r_type])
				elseif is_bad == nil then
					if new_actions[name] == nil then new_actions[name] = {} end
					local act = new_actions[name][parser.r_type]
					if act == nil then
						new_actions[name][parser.r_type] = { ttl=parser.r_ttl, rdata=rdata }
					else -- mutiple RRs: no reordering or deduplication
						if type(act.rdata) ~= 'table' then
							act.rdata = { act.rdata }
						end
						table.insert(act.rdata, rdata)
						if parser.r_ttl ~= act.ttl then -- be conservative
							log('[poli] RPZ %s:%d warning: different TTLs in a set (minimum taken)',
								path, tonumber(parser.line_counter))
							act.ttl = math.min(act.ttl, parser.r_ttl)
						end
					end
				else
					assert(is_bad == false and prefix_labels == 0)
				end
			end
		end

		::continue::
	end
	collectgarbage()
	for qname, rrsets in pairs(new_actions) do
		rules[qname] = policy.ANSWER(rrsets, true)
	end
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

	if watch ~= false then
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

-- Apply an action when query belongs to a slice (determined by slice_func())
function policy.slice(slice_func, ...)
	local actions = {...}
	if #actions <= 0 then
		error('[poli] at least one action must be provided to policy.slice()')
	end

	return function(_, query)
		local index = slice_func(query, #actions)
		return actions[index]
	end
end

-- Initializes slicing function that randomly assigns queries to a slice based on their registrable domain
function policy.slice_randomize_psl(seed)
	local has_psl, psl_lib = pcall(require, 'psl')
	if not has_psl then
		error('[poli] lua-psl is required for policy.slice_randomize_psl()')
	end
	-- load psl
	local has_latest, psl = pcall(psl_lib.latest)
	if not has_latest then -- compatiblity with lua-psl < 0.15
		psl = psl_lib.builtin()
	end

	if seed == nil then
		seed = os.time() / (3600 * 24 * 7)
	end
	seed = math.floor(seed)  -- convert to int

	return function(query, length)
		assert(length > 0)

		local domain = kres.dname2str(query:name())
		if domain == nil then -- invalid data: auto-select first action
			return 1
		end
		if domain:len() > 1 then  --remove trailing dot
			domain = domain:sub(0, -2)
		end

		-- do psl lookup for registrable domain
		local reg_domain = psl:registrable_domain(domain)
		if reg_domain == nil then  -- fallback to unreg. domain
			reg_domain = psl:unregistrable_domain(domain)
			if reg_domain == nil then  -- shouldn't happen: safe fallback
				return 1
			end
		end

		local rand_seed = seed
		-- create deterministic seed for pseudo-random slice assignment
		for i = 1, #reg_domain do
			rand_seed = rand_seed + reg_domain:byte(i)
		end

		-- use lineral congruential generator with values from ANSI C
		rand_seed = rand_seed % 0x80000000  -- ensure seed is positive 32b int
		local rand = (1103515245 * rand_seed + 12345) % 0x10000
		return 1 + rand % length
	end
end

-- Prepare for making an answer from scratch.  (Return the packet for convenience.)
local function answer_clear(req)
	-- If we're in postrules, previous resolving might have chosen some RRs
	-- for inclusion in the answer, so we need to avoid those.
	-- *_selected arrays are in mempool, so explicit deallocation is not necessary.
	req.answ_selected.len = 0
	req.auth_selected.len = 0
	req.add_selected.len = 0

	-- Let's be defensive and clear the answer, too.
	local pkt = req:ensure_answer()
	pkt:clear_payload()
	return pkt
end

function policy.DENY_MSG(msg)
	if msg and (type(msg) ~= 'string' or #msg >= 255) then
		error('DENY_MSG: optional msg must be string shorter than 256 characters')
        end

	return function (_, req)
		-- Write authority information
		local answer = answer_clear(req)
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

local function free_cb(func)
	func:free()
end

local debug_logline_cb = ffi.cast('trace_log_f', function (_, msg)
	jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
	-- msg typically ends with newline
	io.write(ffi.string(msg))
end)
ffi.gc(debug_logline_cb, free_cb)

local debug_logfinish_cb = ffi.cast('trace_callback_f', function (req)
	jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
	ffi.C.kr_log_req(req, 0, 0, 'dbg',
		'following rrsets were marked as interesting:\n' ..
		req:selected_tostring())
	ffi.C.kr_log_req(req, 0, 0, 'dbg',
		'answer packet:\n' ..
		tostring(req.answer))
end)
ffi.gc(debug_logfinish_cb, free_cb)

-- log request packet
function policy.REQTRACE(_, req)
	ffi.C.kr_log_req(req, 0, 0, 'dbg', 'request packet:\n%s',
		tostring(req.qsource.packet))
end

function policy.DEBUG_ALWAYS(state, req)
	policy.QTRACE(state, req)
	req:trace_chain_callbacks(debug_logline_cb, debug_logfinish_cb)
	policy.REQTRACE(state, req)
end

local debug_stashlog_cb = ffi.cast('trace_log_f', function (req, msg)
	jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed

	-- stash messages for conditional logging in trace_finish
	local stash = req:vars()['policy_debug_stash']
	table.insert(stash, ffi.string(msg))
end)
ffi.gc(debug_stashlog_cb, free_cb)

-- buffer verbose logs and print then only if test() returns a truthy value
function policy.DEBUG_IF(test)
	local debug_finish_cb = ffi.cast('trace_callback_f', function (cbreq)
		jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
		if test(cbreq) then
			debug_logfinish_cb(cbreq)  -- unconditional version
			local stash = cbreq:vars()['policy_debug_stash']
			io.write(table.concat(stash, ''))
		end
	end)
	ffi.gc(debug_finish_cb, function (func) func:free() end)

	return function (state, req)
		req:vars()['policy_debug_stash'] = {}
		policy.QTRACE(state, req)
		req:trace_chain_callbacks(debug_stashlog_cb, debug_finish_cb)
		policy.REQTRACE(state, req)
		return
	end
end

policy.DEBUG_CACHE_MISS = policy.DEBUG_IF(
	function(req)
		return not req:all_from_cache()
	end
)

policy.DENY = policy.DENY_MSG() -- compatibility with < 2.0

function policy.DROP(_, req)
	answer_clear(req)
	return kres.FAIL
end

function policy.REFUSE(_, req)
	local answer = answer_clear(req)
	answer:rcode(kres.rcode.REFUSED)
	answer:ad(false)
	return kres.DONE
end

function policy.TC(state, req)
	-- Avoid non-UDP queries
	if req.qsource.flags.tcp then
		return state
	end

	local answer = answer_clear(req)
	answer:tc(1)
	answer:ad(false)
	return kres.DONE
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
	-- RFC8375
	'home.arpa.',
}
policy.todnames(private_zones)

-- @var Default rules
policy.rules = {}
policy.postrules = {}
policy.special_names = {
	-- XXX: beware of special_names_optim() when modifying these filters
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
				todname('local.'), -- RFC 8375.4
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

-- Return boolean; false = no special name may apply, true = some might apply.
-- The point is to *efficiently* filter almost all QNAMEs that do not apply.
local function special_names_optim(req, sname)
	local qname_size = req.qsource.packet.qname_size
	if qname_size < 9 then return true end -- don't want to special-case bad array access
	local root = sname + qname_size - 1
	return
		-- .a???. or .t???.
		(root[-5] == 4 and (root[-4] == 97 or root[-4] == 116))
		-- .on???. or .in?????. or lo???. or *ost.
		or (root[-6] == 5 and root[-5] == 111 and root[-4] == 110)
		or (root[-8] == 7 and root[-7] == 105 and root[-6] == 110)
		or (root[-6] == 5 and root[-5] == 108 and root[-4] == 111)
		or (root[-3] == 111 and root[-2] == 115 and root[-1] == 116)
end

-- Top-down policy list walk until we hit a match
-- the caller is responsible for reordering policy list
-- from most specific to least specific.
-- Some rules may be chained, in this case they are evaluated
-- as a dependency chain, e.g. r1,r2,r3 -> r3(r2(r1(state)))
policy.layer = {
	begin = function(state, req)
		-- Don't act on "finished" cases.
		if bit.band(state, bit.bor(kres.FAIL, kres.DONE)) ~= 0 then return state end
		local qry = req:initial() -- same as :current() but more descriptive
		return policy.evaluate(policy.rules, req, qry, state)
			or (special_names_optim(req, qry.sname)
					and policy.evaluate(policy.special_names, req, qry, state))
			or state
	end,
	finish = function(state, req)
		-- Optimization for the typical case
		if #policy.postrules == 0 then return state end
		-- Don't act on failed cases.
		if bit.band(state, kres.FAIL) ~= 0 then return state end
		return policy.evaluate(policy.postrules, req, req:initial(), state) or state
	end
}

return policy
