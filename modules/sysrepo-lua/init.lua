local sysrepo_ffi = require("kres_modules/sysrepo-lua/ffi")
 -- following require returns only module constructor, calling it straight away
local data_model = require("kres_modules/sysrepo-lua/model")(sysrepo_ffi.get_clib_bindings())

local sysrepo = {}

local function apply_configuration(root_node)
    print("Configuration has changed. Applying the new config!")

    data_model.apply_configuration(root_node)
end

local function read_configuration()
    print("Current configuration requested")

    return data_model.serialize_configuration(nil)
end

function sysrepo.init()
    sysrepo_ffi.init(apply_configuration, read_configuration)
end

function sysrepo.deinit()
    sysrepo_ffi.deinit()
end

return sysrepo
