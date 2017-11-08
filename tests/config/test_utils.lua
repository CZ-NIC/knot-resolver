function fail(fmt, ...)
        io.stderr:write(string.format(fmt..'\n', ...))
	os.exit(2)
end

function table_keys_to_lower(table)
	res = {}
	for k, v in pairs(table) do 
                res[k:lower()] = v
        end
	return res
end

function contains(table, value)
	for k,v in pairs(table) do
		if v == value then
			return true
		end
	end
	return false	
end
