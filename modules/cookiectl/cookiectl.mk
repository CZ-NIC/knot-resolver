cookiectl_CFLAGS := -fvisibility=hidden -fPIC
cookiectl_SOURCES := \
	modules/cookiectl/cookiectl.c
cookiectl_DEPEND := $(libkres)
cookiectl_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cookiectl)
