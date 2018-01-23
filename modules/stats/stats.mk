stats_CFLAGS := -fPIC
stats_SOURCES := modules/stats/stats.c
stats_DEPEND := $(libkres)
stats_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,stats)
