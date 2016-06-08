http_SOURCES := http.lua prometheus.lua
http_INSTALL := $(wildcard modules/http/static/*) \
                modules/http/http/h2_connection.lua \
                modules/http/http/server.lua
$(call make_lua_module,http)
