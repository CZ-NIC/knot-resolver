local ffi = require("ffi")

local M = {}

-- returns nil on success or an error string
-- TODO no self??
function M:set_leaf_conf(userdata_val)
    -- val is a pointer to sr_val_t

    local val = ffi.cast("sr_val_t*", userdata_val)()
    print("Configuration change")
    print("\t" .. tostring(val))

    return "Not implemented yet"
end

return M
