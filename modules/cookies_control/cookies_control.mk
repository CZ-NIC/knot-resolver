cookies_control_CFLAGS := -fvisibility=hidden -fPIC
cookies_control_SOURCES := \
	modules/cookies_control/cookies_control.c
cookies_control_DEPEND := $(libkres)
cookies_control_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cookies_control)
