-- optional code coverage
-- include this file into config if you want to generate coverage data

local ok, runner = pcall(require, 'luacov.runner')
if ok then
	runner.init({
		savestepsize = 2, -- TODO
		statsfile = 'luacov.stats.out',
		exclude = {'test', 'tapered'},
	})
	jit.off()
end
