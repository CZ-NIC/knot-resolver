-- SPDX-License-Identifier: GPL-3.0-or-later
local M = {} -- the module

local ffi = require('ffi')

function M.config(cfg)
	if not cfg then return end

	-- Beware that the timeout is only considered at certain points in time;
	-- approximately at multiples of KR_CONN_RTT_MAX.
	M.timeout = cfg.timeout or 3*sec

	local targets_split = policy.forward_convert_targets(cfg.options, cfg.targets)

	M.targets_ptr = ffi.new('knot_db_val_t')
	M.targets_ptr.len = #cfg.targets * ffi.C.KR_SOCKADDR_SIZE
	M.targets_ptr_data = ffi.new('char [?]', #cfg.targets * ffi.C.KR_SOCKADDR_SIZE)
	M.targets_ptr.data = M.targets_ptr_data -- TODO: explain
	ffi.C.kr_rule_coalesce_targets(targets_split, M.targets_ptr.data)
end

M.layer = {}
M.layer.produce = function (state, req, pkt)
	if not M.targets_ptr or state == kres.FAIL or state == kres.DONE then return state end

	local qry = req:current()
	-- Don't do anything for priming, prefetching, etc.
	-- TODO: not all cases detected ATM.
	if qry.flags.NO_CACHE then return state end

	-- FIXME: also check the source of traffic
	local now = ffi.C.kr_now()
	local deadline = qry.creation_time_mono + M.timeout
	if now > deadline or qry.flags.NO_NS_FOUND then
		log_qry(qry, ffi.C.LOG_GRP_SRVSTALE,
			'   => no reachable NS, activating fallback forwarding',
			kres.dname2str(qry:name()))
		
		qry.data_src.initialized = true
		qry.data_src.all_set = false
		qry.data_src.rule_depth = 0
		qry.data_src.flags.is_auth = false
		qry.data_src.flags.is_tcp = true   -- FIXME
		qry.data_src.flags.is_nods = false
		qry.data_src.targets_ptr = M.targets_ptr
		qry.flags.FORWARD = true
		qry.flags.STUB = false
		if qry.data_src.flags.is_tcp then qry.flags.TCP = true end
		ffi.C.kr_make_query(qry, pkt)
	end

	return state
end

return M

