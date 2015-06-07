hints_SOURCES := modules/hints/hints.c contrib/ccan/json/json.c
hints_DEPEND := $(libkres)
hints_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,hints)