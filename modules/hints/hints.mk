hints_CFLAGS := -fvisibility=hidden -fPIC
hints_SOURCES := modules/hints/hints.c
hints_DEPEND := $(libkres)
hints_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,hints)