version_SOURCES := version.lua

modules/version/version.lua: modules/version/version.lua.in
	$(SED) -e "s/@VERSION@/$(VERSION)/" < "$<" > "$@"

$(call make_lua_module,version)
