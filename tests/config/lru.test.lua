-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

-- Test LRU interface
local function test_lru()
	local capacity = 1024
	local lru = kres.lru(capacity)
	local dict = {
		"catagmatic", "prevaricator", "statoscope", "workhand", "benzamide",
		"alluvia", "fanciful", "bladish", "Tarsius", "unfast", "appropriative",
		"seraphically", "monkeypod", "deflectometer", "tanglesome", "zodiacal",
		"physiologically", "economizer", "forcepslike", "betrumpet",
		"Danization", "broadthroat", "randir", "usherette", "nephropyosis",
		"hematocyanin", "chrysohermidin", "uncave", "mirksome", "podophyllum",
		"siphonognathous", "indoor", "featheriness", "forwardation",
		"archruler", "soricoid", "Dailamite", "carmoisin", "controllability",
		"unpragmatical", "childless", "transumpt", "productive",
		"thyreotoxicosis", "oversorrow", "disshadow", "osse", "roar",
		"pantomnesia", "talcer", "hydrorrhoea", "Satyridae", "undetesting",
		"smoothbored", "widower", "sivathere", "pendle", "saltation",
		"autopelagic", "campfight", "unexplained", "Macrorhamphosus",
		"absconsa", "counterflory", "interdependent", "triact", "reconcentration",
		"oversharpness", "sarcoenchondroma", "superstimulate", "assessory",
		"pseudepiscopacy", "telescopically", "ventriloque", "politicaster",
		"Caesalpiniaceae", "inopportunity", "Helion", "uncompatible",
		"cephaloclasia", "oversearch", "Mahayanistic", "quarterspace",
		"bacillogenic", "hamartite", "polytheistical", "unescapableness",
		"Pterophorus", "cradlemaking", "Hippoboscidae", "overindustrialize",
		"perishless", "cupidity", "semilichen", "gadge", "detrimental",
		"misencourage", "toparchia", "lurchingly", "apocatastasis"
	}

	-- Check that key insertion works
	local inserted = 0
	for i, word in ipairs(dict) do
		if lru:set(word, i) then
			if lru:get(word) == i then
				inserted = inserted + 1
			end
		end
	end

	is(inserted, #dict, 'all inserted keys can be retrieved')

	-- Check that using binary data as keys works
	local badinserts = 0
	for i, word in ipairs(dict) do
		local word_len = #word
		word = ffi.cast('char *', word)
		if lru:set(word, i, word_len) then
			if lru:get(word, word_len) ~= i then
				badinserts = badinserts + 1
			end
		end
	end

	is(badinserts, 0, 'insertion works for binary keys')

	-- Sanity check that non-existent keys cannot be retrieved
	local missing = "not in lru"
	is(lru:get(missing, #missing, false), nil, 'key that wasnt inserted cannot be retrieved')

	-- Test whether key eviction works and LRU is able to insert past the capacity
	badinserts = 0
	for i = 0, capacity do
		local word = dict[1] .. tostring(i)
		if lru:set(word, i) then
			if lru:get(word) ~= i then
				badinserts = badinserts + 1
			end
		end
	end

	is(badinserts, 0, 'insertion works for more keys than LRU capacity')

	-- Delete and GC
	lru = nil -- luacheck: ignore 311
	collectgarbage()
	collectgarbage()
end

return {
	test_lru,
}
