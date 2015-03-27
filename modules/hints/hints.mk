hints_SOURCES := modules/hints/hints.c
hints_DEPEND := $(libkresolve)
hints_LIBS := $(libkresolve_TARGET) $(libkresolve_LIBS)
$(call make_c_module,hints)