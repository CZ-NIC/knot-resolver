-- SPDX-License-Identifier: GPL-3.0-or-later
local M = {}

function M.test(f, ...)
	local res, exception = xpcall(f, debug.traceback, ...)
	if not res then
		io.stderr:write(string.format('%s\n', exception))
		os.exit(2)
	end
	return res
end

function M.table_keys_to_lower(table)
	local res = {}
	for k, v in pairs(table) do
		res[k:lower()] = v
	end
	return res
end

local function contains(pass, fail, table, value, message)
	message = message or string.format('table contains "%s"', value)
	for _, v in pairs(table) do
		if v == value then
			pass(message)
			return
		end
	end
	fail(message)
	return
end

function M.contains(table, value, message)
	return contains(pass, fail, table, value, message)
end

function M.not_contains(table, value, message)
	return contains(fail, pass, table, value, message)
end

local function rrset_to_texts(rr)
	local rr_text = {}
	for w in rr:txt_dump():gmatch("%S+") do table.insert(rr_text, w) end
	return rr_text
end

local function answer2table(pkt)
	local got_answers = {}
	local ans_rrs = pkt:rrsets(kres.section.ANSWER)
	for i = 1, #ans_rrs do
		rrs = ans_rrs[i]
		for rri = 0, rrs:rdcount() - 1 do
			local rr = ans_rrs[i]:txt_fields(rri)
			got_answers[rr.owner] = got_answers[rr.owner] or {}
			got_answers[rr.owner][rr.type] = got_answers[rr.owner][rr.type] or {}
			table.insert(got_answers[rr.owner][rr.type], rr.rdata)
			table.sort(got_answers[rr.owner][rr.type])
		end
	end
	return got_answers
end

M.NODATA = -1
-- Resolve a name and check the answer.  Do *not* return until finished.
-- expected_rdata is one string or a table of strings in presentation format
function M.check_answer(desc, qname, qtype, expected_rcode, expected_rdata)
	assert(type(qtype) == 'number')
	local qtype_str = kres.tostring.type[qtype]
	qname = string.lower(qname)

	local expected_answer = {}
	if expected_rdata ~= nil then
		if type(expected_rdata) ~= 'table' then
			expected_rdata = { expected_rdata }
		end
		if #expected_rdata > 0 then
			table.sort(expected_rdata)
			expected_answer = {
				[qname] = {
					[qtype_str] =
						expected_rdata
				}
			}
		end
	end

	local wire_rcode = expected_rcode
	if expected_rcode == kres.rcode.NOERROR and type(expected_rdata) == 'table'
			and #expected_rdata == 0 then
		expected_rcode = M.NODATA
	end
	if expected_rcode == M.NODATA then wire_rcode = kres.rcode.NOERROR end

	local done = false
	local callback = function(pkt)
		same(pkt:rcode(), wire_rcode,
		     desc .. ': expecting answer for query ' .. qname .. ' ' .. qtype_str
		      .. ' with rcode ' .. kres.tostring.rcode[wire_rcode])

		ok((pkt:ancount() > 0) == (expected_rcode == kres.rcode.NOERROR),
		   desc ..': checking number of answers for ' .. qname .. ' ' .. qtype_str)

		if expected_rdata then
			same(expected_answer, answer2table(pkt), 'ANSWER section matches')
		end
		done = true
	end
	resolve(qname, qtype, kres.class.IN, {},
		function(...)
			local ok, err = xpcall(callback, debug.traceback, ...)
			if not ok then
				fail('error in check_answer callback function')
				io.stderr:write(string.format('%s\n', err))
				os.exit(2)
			end
		end
	)

	for delay = 0.1, 4, 0.5 do -- total max 14.9s in 8 steps
		if done then return end
		worker.sleep(delay)
	end
	if not done then fail('check_answer() timed out') end
end

return M
