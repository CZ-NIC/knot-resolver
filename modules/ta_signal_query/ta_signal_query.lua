-- Module implementing RFC 8145 section 5
-- Signaling Trust Anchor Knowledge in DNS using Key Tag Query
local kres = require('kres')

local M = {}
M.layer = {}

-- transform trust anchor keyset structure for one domain name (in wire format)
-- to signalling query name like _ta-keytag1-keytag2.example.com.
-- Returns:
--   string constructed from valid keytags
--   nil if no valid keytag is present in keyset
local function prepare_query_name(keyset, name)
	if not keyset then return nil end
	local keytags = {}
	for _, key in ipairs(keyset) do
		if key.state == "Valid" then
			table.insert(keytags, key.key_tag)
		end
	end
	if next(keytags) == nil then return nil end

	table.sort(keytags)
	local query = "_ta"
	for _, tag in pairs(keytags) do
		query = string.format("%s-%04x", query, tag)
	end
	if name == "\0" then
		return query .. "."
	else
		return query .. "." .. kres.dname2str(name)
	end
end

-- construct keytag query for valid keys and send it as asynchronous query
-- (does nothing if no valid keys are present at given domain name)
local function send_ta_query(domain)
	local keyset = trust_anchors.keysets[domain]
	local qname = prepare_query_name(keyset, domain)
	if qname ~= nil then
		if verbose() then
			log("[ta_signal_query] signalling query trigered: %s", qname)
		end
		-- asynchronous query
		-- we do not care about result or from where it was obtained
		event.after(0, function ()
			resolve(qname, kres.type.NULL, kres.class.IN, "NONAUTH")
		end)
	end
end

-- act on DNSKEY queries which were not answered from cache
function M.layer.consume(state, req, _)
	req = kres.request_t(req)
	local qry = req:current()
	if qry.stype == kres.type.DNSKEY and not qry.flags.CACHED then
		send_ta_query(qry:name())
	end
	return state  -- do not interfere with normal query processing
end

return M
