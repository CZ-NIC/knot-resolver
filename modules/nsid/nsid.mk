nsid_CFLAGS := -fPIC
nsid_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
nsid_SOURCES := modules/nsid/nsid.c
nsid_DEPEND := $(libkres)
nsid_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,nsid)
