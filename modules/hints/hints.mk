hints_SOURCES := modules/hints/hints.c contrib/ccan/json/json.c
hints_DEPEND := $(libkresolve)
hints_LIBS := $(libkresolve_TARGET) $(libkresolve_LIBS)
$(call make_c_module,hints)