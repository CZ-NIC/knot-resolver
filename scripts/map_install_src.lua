#!/usr/bin/env luajit
-- SPDX-License-Identifier: GPL-3.0-or-later

-- parse install commands from stdin
-- input: PREFIX=... make install --dry-run --always-make
-- output: <install path> <source path>
-- (or sed commands if --sed was specified)

output = 'list'
if #arg > 1 or arg[1] == '-h' or arg[1] == '--help' then
	print(string.format([[
Read install commands and map install paths to paths in source directory.

Usage:
$ PREFIX=... make install --dry-run --always-make | %s

Example output:
/kresd/git/.local/lib/kdns_modules/policy.lua	modules/policy/policy.lua

Option --sed will produce output suitable as input suitable for sed.]],
				arg[0]))
	os.exit(1)
elseif #arg == 0 then
	output = 'list'
elseif arg[1] == '--sed' then
	output = 'sed'
else
	print('Invalid arguments. See --help.')
	os.exit(2)
end

-- remove double // from paths and remove trailing /
function normalize_path(path)
	assert(path)
	repeat
		path, changes = path:gsub('//', '/')
	until changes == 0
	return path:gsub('/$', '')
end

function is_opt(word)
	return word:match('^-')
end

-- opts requiring additional argument to be skipped
local ignored_opts_with_arg = {
	['--backup'] = true,
	['-g'] = true,
	['--group'] = true,
	['-m'] = true,
	['--mode'] = true,
	['-o'] = true,
	['--owner'] = true,
	['--strip-program'] = true,
	['--suffix'] = true,
}

-- state machine junctions caused by --opts
-- returns: new state (expect, mode) and target name if any
function parse_opts(word, expect, mode)
	if word == '--' then
		return 'names', mode, nil -- no options anymore
	elseif word == '-d' or word == '--directory' then
		return 'opt_or_name', 'newdir', nil
	elseif word == '-t' or word == '--target-directory' then
		return 'targetdir', mode, nil
	elseif word:match('^--target-directory=') then
		return 'opt_or_name', mode, string.sub(word, 20)
	elseif ignored_opts_with_arg[word] then
		return 'ignore', mode, nil -- ignore next word
	else
		return expect, mode, nil -- unhandled opt
	end
end


-- cmd: complete install command line: install -m 0644 -t dest src1 src2
-- dirs: names known to be directories: name => true
-- returns: updated dirs
function process_cmd(cmd, dirs)
	-- print('# ' .. cmd)
	sanity_check(cmd)
	local expect = 'install'
	local mode = 'copy' -- copy or newdir
	local target -- last argument or argument for install -t
	local names = {} -- non-option arguments

	for word in cmd:gmatch('%S+') do
		if expect == 'install' then -- parsing 'install'
			assert(word == 'install')
			expect = 'opt_or_name'
		elseif expect == 'opt_or_name' then
			if is_opt(word) then
				expect, mode, newtarget = parse_opts(word, expect, mode)
				target = newtarget or target
			else
				if mode == 'copy' then
					table.insert(names, word)
				elseif mode == 'newdir' then
					local path = normalize_path(word)
					dirs[path] = true
				else
					assert(false, 'bad mode')
				end
			end
		elseif expect == 'targetdir' then
			local path = normalize_path(word)
			dirs[path] = true
			target = word
			expect = 'opt_or_name'
		elseif expect == 'names' then
			table.insert(names, word)
		elseif expect == 'ignore' then
			expect = 'opt_or_name'
		else
			assert(false, 'bad expect')
		end
	end
	if mode == 'newdir' then
		-- no mapping to print, this cmd just created directory
		return dirs
	end

	if not target then -- last argument is the target
		target = table.remove(names)
	end
	assert(target, 'fatal: no target in install cmd')
	target = normalize_path(target)

	for _, name in pairs(names) do
		basename = string.gsub(name, "(.*/)(.*)", "%2")
		if not dirs[target] then
			print('fatal: target directory "' .. target .. '" was not created yet!')
			os.exit(2)
		end
		-- mapping installed name -> source name
		if output == 'list' then
			print(target .. '/' .. basename, name)
		elseif output == 'sed' then
			print(string.format([[s`%s`%s`g]],
					    target .. '/' .. basename, name))
		else
			assert(false, 'unsupported output')
		end
	end
	return dirs
end

function sanity_check(cmd)
	-- shell quotation is not supported
	assert(not cmd:match('"'), 'quotes " are not supported')
	assert(not cmd:match("'"), "quotes ' are not supported")
	assert(not cmd:match('\\'), "escapes like \\ are not supported")
	assert(cmd:match('^install%s'), 'not an install command')
end

-- remember directories created by install -d so we can expand relative paths
local dirs = {}
while true do
	local cmd = io.read("*line")
	if not cmd then
		break
	end
	local isinstall = cmd:match('^install%s')
	if isinstall then
		dirs = process_cmd(cmd, dirs)
	end
end
