version_SOURCES := version.lua

modules/version/version.lua: modules/version/version.lua.in
	@$(call quiet,SED,$<) -e "s/@VERSION@/$(VERSION)/" $< > $@

$(call make_lua_module,version)

version-clean:
	@$(call quiet,RM,modules/version/version.lua) modules/version/version.lua

.PHONY: version-clean
