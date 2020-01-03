local sysrepo_ffi = require("kres_modules/sysrepo_ffi")

local sysrepo = {}

local function apply_configuration(sr_val)
    local sr_val_table = sysrepo_ffi.sr_val_to_table(sr_val)

    print("Configuration change")
    print(tostring(sr_val_table))
end

function sysrepo.init()
    sysrepo_ffi.init(apply_configuration)
end

function sysrepo.deinit()
    sysrepo_ffi.deinit()
end

return sysrepo
