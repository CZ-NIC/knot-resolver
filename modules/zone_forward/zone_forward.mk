zone_forward_CFLAGS := -fPIC
zone_forward_SOURCES := modules/zone_forward/zone_forward.c
zone_forward_DEPEND := $(libkres)
zone_forward_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,zone_forward)
