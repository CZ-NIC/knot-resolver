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

function debug.dump_table(table, indent)
    if indent == nil then indent = 0 end

    if table == nil then
        debug.log("table is nil")
        return
    end

    if indent == 0 then debug.log("{") end
    for k,v in pairs(table) do
        local space = string.rep(' ', (indent+1)*2)
        if type(v) == 'table' then
            debug.log(space .. "[" .. tostring(k) .. "] = {")
            debug.dump_table(v, indent+1)
            debug.log(space .. "},")
        else
            debug.log(space .. "[" .. tostring(k) .. "] = \"" .. tostring(v) .. "\", -- (" .. type(v) .. ")")
        end
    end
    if indent == 0 then debug.log("}") end
end

return debug
