local M = {}

local function getLastWord(str)
    local space = 1
    for i=#str, 1, -1 do
        if str:sub(i,i) == " " then
            space = i
            break
        end
    end
    return str:sub(space+1, #str)
end

--Converts string of HEX digits to string
local function hex2string(hex)
    local str = ""
    for i=1, #hex, 2 do
        local ascii = tonumber(hex:sub(i,i+1), 16)
        str = str .. string.char(ascii)
    end
    return str
end

--Runs "kresd -V" to get installed version
local function getLocalVersion()
    local file = io.popen("kresd -V")
    local version = file:read('*all')
    file:close()
    version = getLastWord(version):sub(1,-2)
    return version
end

local function parseCVE(str)
    local first
    local last
    first, last = str:find("CVE")
    local position = last+2
    return str:sub(position,-1)
end
    
local function parseVersion(str)
    local branch = "stable"
    local first
    local last
    first, last = str:find(branch)
    local position = last+3
    local delimiter = #str
    if str:find("|",position) then
        delimiter = str:find("|",position)-1
    end
    return str:sub(position, delimiter)
end

--Parses version from server and compares it to the installed one
local function parse(record)
    local output = ""
    local str = getLastWord(kres.rr2str(record))
    str = hex2string(str)
    local CVE = parseCVE(str)
    local version = parseVersion(str)
    local localVersion = getLocalVersion()
    if version ~= localVersion then
        output = output .. string.format("[version] Newer version of Knot DNS Resolver is available. (Current: %s, Available: %s)\n", localVersion, version)
    end
    if CVE ~= "N/A" then
        output = output .. string.format("[version] CVE: %s\n", CVE)
    end
    io.write(output)
end

--Parses record from answer
local function request (answer)
    local pkt = kres.pkt_t(answer)
    if pkt:rcode() == kres.rcode.NOERROR then
        parse(pkt:section(kres.section.ANSWER)[1])
    else
        print ('Request for version ended with rcode: ', pkt:rcode())
        return
    end
end

function M.init()
    resolve('et.knot-resolver.cz', kres.type.TXT, kres.class.IN, 0, request)
end

return M