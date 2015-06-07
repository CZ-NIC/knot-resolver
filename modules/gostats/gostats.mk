gostats_SOURCES := modules/gostats/gostats.go
gostats_DEPEND := $(libkres)
gostats_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_go_module,gostats)