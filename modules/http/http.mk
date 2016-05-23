http_SOURCES := http.lua
http_INSTALL := $(wildcard modules/http/static/*)
$(call make_lua_module,http)
