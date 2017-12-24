# Measure code coverage using luacov and gcov
# C and Lua code is measured separately and resutls are combined together
# Define COVERAGE=1 during build *and* test runs to enable measurement.
#
# Beware: Tests are typically run in parallel and neither luacov not gcov
# support that, so we have to store results from each run separatelly
# and combine them.

coverage-c-combine-gcda:
	@# combine trees of gcda files into one info file per tree
	@mkdir -p '$(COVERAGE_STATSDIR)/tmp.c'
	@LCOV=$(LCOV) ./scripts/coverage_c_combine.sh '$(TOPSRCDIR)' '$(COVERAGE_STATSDIR)' '$(COVERAGE_STATSDIR)/tmp.c'

coverage-c: coverage-c-combine-gcda
	@# combine info files for each tree into resulting c.info file
	@$(LCOV) -q $(addprefix --add-tracefile ,$(wildcard $(COVERAGE_STATSDIR)/tmp.c/*.info)) --output-file '$(COVERAGE_STAGE).c.info'
	@$(RM) -r '$(COVERAGE_STATSDIR)/tmp.c'

LUA_STATS_OUT := $(shell find '$(COVERAGE_STATSDIR)' -type f -name 'luacov.stats.out')
LUA_INFOS_OUT := $(patsubst %.stats.out,%.lua.info,$(LUA_STATS_OUT))

coverage-lua-fix-paths: $(LUA_STATS_OUT)
	@# map Lua install paths to source paths
	@$(MAKE) PREFIX=$(PREFIX) install --dry-run --always-make | scripts/map_install_src.lua --sed > .luacov_path_map
	@sed -i -f .luacov_path_map $^
	@$(RM) .luacov_path_map

luacov.empty_stats.out:
	@# generate list of all Lua files to fill holes in luacov stats
	@$(MAKE) PREFIX=$(PREFIX) install --dry-run --always-make | scripts/map_install_src.lua | cut -f 2 | grep '\.lua$$' | scripts/luacov_gen_empty.sh > luacov.empty_stats.out

%.lua.info: %.stats.out coverage-lua-fix-paths
	@scripts/luacov_to_info.lua $*.stats.out > $@

coverage-lua: $(LUA_INFOS_OUT) luacov.empty_stats.out
	@echo '# Lua coverage in $(COVERAGE_STAGE).lua.info'
	@# add missing files to luacov stats
	@scripts/luacov_to_info.lua luacov.empty_stats.out > luacov.empty_stats.lua.info
	@# combine info files for each tree into resulting lua.info file
	@$(LCOV) -q $(addprefix --add-tracefile ,$(LUA_INFOS_OUT)) --add-tracefile luacov.empty_stats.lua.info --output-file '$(COVERAGE_STAGE).lua.info'
	@$(RM) luacov.empty_stats.out luacov.empty_stats.lua.info

coverage:
	@$(LCOV) $(addprefix --add-tracefile ,$(wildcard $(COVERAGE_STAGE)*.info)) --output-file coverage.info
	@$(GENHTML) --no-function-coverage --no-branch-coverage -q -o coverage -p '$(realpath $(CURDIR))' -t 'Knot DNS Resolver $(VERSION)-$(PLATFORM) coverage report' --legend coverage.info

coverage-clean:
	@$(RM) -rf '$(COVERAGE_STATSDIR)'

.PHONY: coverage-c-combine-gcda coverage-c coverage-lua-fix-paths coverage-lua coverage coverage-clean

# Options
ifdef COVERAGE
BUILD_CFLAGS += --coverage
endif
