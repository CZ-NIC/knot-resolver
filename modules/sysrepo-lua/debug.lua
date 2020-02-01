local debug = {}

local DEBUGGING_ENABLED = true

local function pack_table(...)
    return { n = select("#", ...), ... }
end


function debug.log(msg, ...)
    if not DEBUGGING_ENABLED then
        return
    end

    local args = pack_table(...)
    for i=1,args.n do
        msg = string.gsub(msg, "{}", tostring(args[i]), 1)
    end

    print("[LUA DEBUG] " .. msg)
end

return debug
