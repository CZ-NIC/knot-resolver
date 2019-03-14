http_SOURCES := http.lua prometheus.lua dns_over_https.lua http_trace.lua
http_INSTALL := $(wildcard modules/http/static/*)
$(call make_lua_module,http)
