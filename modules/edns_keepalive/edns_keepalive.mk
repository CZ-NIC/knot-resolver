edns_keepalive_CFLAGS := -fPIC
edns_keepalive_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
edns_keepalive_SOURCES := modules/edns_keepalive/edns_keepalive.c
$(call make_c_module,edns_keepalive)

