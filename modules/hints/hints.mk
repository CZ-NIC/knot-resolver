hints_CFLAGS := -fvisibility=hidden
hints_SOURCES := modules/hints/hints.c
hints_DEPEND := $(libkres)
hints_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,hints)