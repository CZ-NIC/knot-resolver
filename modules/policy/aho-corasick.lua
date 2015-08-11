-- A Lua implementation of the Aho-Corasick string matching algorithm
--
-- Copyright (c) 2013 CloudFlare, Inc. All rights reserved.
-- 
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are
-- met:
-- 
--    * Redistributions of source code must retain the above copyright
-- notice, this list of conditions and the following disclaimer.
--    * Redistributions in binary form must reproduce the above
-- copyright notice, this list of conditions and the following disclaimer
-- in the documentation and/or other materials provided with the
-- distribution.
--    * Neither the name of CloudFlare, Inc. nor the names of its
-- contributors may be used to endorse or promote products derived from
-- this software without specific prior written permission.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
-- "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
-- LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
-- A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
-- OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
-- SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
-- LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
-- DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
-- THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-- (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
-- OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--
-- Usage:
--
-- local AC = require 'aho-corasick'
--
-- t = AC.build({'words', 'to', 'find'})
-- r = AC.match(t, 'try to find in this string')
-- r == {'to', 'find'}

local M = {}
local byte = string.byte
local char = string.char

local root = ""

-- make: creates a new entry in t for the given string c with optional fail
-- state
local function make(t, c, f)
    t[c]      = {}
    t[c].to   = {}
    t[c].fail = f
    t[c].hit  = root
    t[c].word = false
end

-- build: builds the Aho-Corasick data structure from an array of strings
function M.build(m)
    local t = {}
    make(t, root, root)

    for i = 1, #m do
        local current = root

        -- Build the tos which capture the transitions within the tree

        for j = 1, m[i]:len() do
            local c = byte(m[i], j)
            local path = current .. char(c)

            if t[current].to[c] == nil then
                t[current].to[c] = path

                if current == root then
                    make(t, path, root)
                else
                    make(t, path)
                end
            end

            current = path
        end

        t[m[i]].word = true
    end

    -- Build the fails which show how to backtrack when a fail matches and
    -- build the hits which connect nodes to suffixes that are words

    local q = {root}

    while #q > 0 do
        local path = table.remove(q, 1)

        for c, p in pairs(t[path].to) do
            table.insert(q, p)

            local fail = p:sub(2)
            while fail ~= "" and t[fail] == nil do
                fail = fail:sub(2)
            end
            if fail == "" then fail = root end
            t[p].fail = fail

            local hit = p:sub(2)
            while hit ~= "" and (t[hit] == nil or not t[hit].word) do
                hit = hit:sub(2)
            end
            if hit == "" then hit = root end
            t[p].hit = hit
        end
    end

    return t
end

-- match: checks to see if the passed in string matches the passed in tree
-- created with build. If all is true (the default) an array of all matches is
-- returned. If all is false then only the first match is returned.
function M.match(t, s, all)
    if all == nil then
        all = true
    end

    local path = root
    local hits = {}
    local hits_idx = 0

    for i = 1,s:len() do
        local c = byte(s, i)

        while t[path].to[c] == nil and path ~= root do
            path = t[path].fail
        end

        local n = t[path].to[c]

        if n ~= nil then
            path = n

            if t[n].word then
                hits_idx = hits_idx + 1
                hits[hits_idx] = n
            end

            while t[n].hit ~= root do
                n = t[n].hit
                hits_idx = hits_idx + 1
                hits[hits_idx] = n
            end

            if all == false and hits_idx > 0 then
                return hits
            end
        end
    end

    return hits
end

return M