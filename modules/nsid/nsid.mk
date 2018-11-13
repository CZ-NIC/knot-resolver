nsid_CFLAGS := -fPIC
nsid_SOURCES := modules/nsid/nsid.c
nsid_DEPEND := $(libkres)
nsid_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,nsid)
