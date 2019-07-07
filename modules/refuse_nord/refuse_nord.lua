local kres = require('kres')

local M = {}
M.layer = {}

function M.layer.begin(state, req)
	req = kres.request_t(req)
	if not req.qsource.packet:rd() then
		local answer = req.answer
		answer:rcode(kres.rcode.REFUSED)
		answer:ad(false)
		return kres.DONE
	end
end

return M
