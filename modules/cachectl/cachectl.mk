cachectl_CFLAGS := -fvisibility=hidden -fPIC
cachectl_SOURCES := modules/cachectl/cachectl.c
cachectl_DEPEND := $(libkres)
cachectl_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cachectl)