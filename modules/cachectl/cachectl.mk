cachectl_CFLAGS := -fvisibility=hidden -fPIC
cachectl_SOURCES := modules/cachectl/cachectl.c
cachectl_DEPEND := $(libkres)
cachectl_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cachectl)