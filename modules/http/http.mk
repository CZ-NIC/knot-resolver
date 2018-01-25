http_SOURCES := http.lua prometheus.lua http_trace.lua
http_INSTALL := $(wildcard modules/http/static/*)
$(call make_lua_module,http)
