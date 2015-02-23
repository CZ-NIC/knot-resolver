hints_SOURCES := modules/gostats/gostats.g
gostats_DEPEND := libkresolve
gostats_LIBS := $(libkresolve_TARGET) $(libkresolve_LIBS)
$(call make_go_module,gostats)