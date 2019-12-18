
-- Get length of table
function kr_table_len (t)
	local len = 0
	for _ in pairs(t) do
		len = len + 1
	end
	return len
end

