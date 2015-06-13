stats_SOURCES := modules/stats/stats.c contrib/ccan/json/json.c
stats_DEPEND := $(libkres)
stats_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,stats)
