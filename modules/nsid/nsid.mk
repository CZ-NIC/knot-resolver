nsid_CFLAGS := -fPIC
# We use a symbol that's not in libkres but the daemon.
# On darwin this isn't accepted by default.
nsid_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
nsid_SOURCES := modules/nsid/nsid.c
nsid_DEPEND := $(libkres)
nsid_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,nsid)
