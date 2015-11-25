stats_CFLAGS := -fvisibility=hidden
stats_SOURCES := modules/stats/stats.c
stats_DEPEND := $(libkres)
stats_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,stats)
