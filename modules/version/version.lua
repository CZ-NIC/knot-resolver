local M = {}

local function parseCVE(str)
    local _, last = str:find('CVE')
    if last then
        return str:sub(last + 2, -1)
    end
end

local function parseVersion(str)
    local branch = 'stable'
    local _, last = str:find(branch)
    if last then
        local position = last+3
        local delimiter = #str
        if str:find("|",position) then
            delimiter = str:find("|",position)-1
        end
        return str:sub(position, delimiter)
    end
end

--Parses version from server and compares it to the installed one
local function parse(rr)
    local str = rr:tostring(0)
    local CVE = parseCVE(str) or 'N/A'
    local latestVersion = parseVersion(str) or ''
    local current = package_version()
    if latestVersion > current then
        log('[version] Current version of Knot DNS Resolver is different from the latest stable one available.'
			.. ' (Current: %s, Latest stable: %s)', current, latestVersion)
		if CVE ~= 'N/A' then
			warn('[version] CVE: %s', CVE)
		end
    end
end

--Parses record from answer
local function check_version(answer)
    local pkt = kres.pkt_t(answer)
    local answers = pkt:rrsets(kres.section.ANSWER)
    if pkt:rcode() == kres.rcode.NOERROR and #answers > 0 then
        parse(answers[1])
    else
        log('[version] response for version was empty or failed, rcode: ', pkt:rcode())
    end
end

function M.config(period)
    M.period = tonumber(period) or 1 * day
    if M.ev then event.cancel(M.ev) end
    M.ev = event.recurrent(M.period, function ()
        resolve {
            name = 'et.knot-resolver.cz',
            type = kres.type.TXT,
            finish = check_version,
        }
    end)
end

function M.deinit()
    if M.ev then event.cancel(M.ev) end
end

return M
