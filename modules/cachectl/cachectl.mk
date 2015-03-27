cachectl_SOURCES := modules/cachectl/cachectl.c
cachectl_DEPEND := $(libkresolve)
cachectl_LIBS := $(libkresolve_TARGET) $(libkresolve_LIBS)
$(call make_c_module,cachectl)