edns_keepalive_CFLAGS := -fPIC
# We use a symbol that's not in libkres but the daemon.
# On darwin this isn't accepted by default.
edns_keepalive_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
edns_keepalive_SOURCES := modules/edns_keepalive/edns_keepalive.c
#edns_keepalive_DEPEND := $(libkres)
#edns_keepalive_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,edns_keepalive)

