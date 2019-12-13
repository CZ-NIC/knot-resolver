
-- Module API
local kluautil = {
	-- Get length of table
	tableLen  = function (t)
		local len = 0
		for _ in pairs(t) do len = len + 1 end
		return len
	end,
}

return kluautil
