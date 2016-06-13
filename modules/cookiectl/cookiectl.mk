cookiectl_CFLAGS := -fvisibility=hidden -fPIC
cookiectl_SOURCES := \
	modules/cookiectl/contrib/openbsd/strlcat.c \
	modules/cookiectl/contrib/openbsd/strlcpy.c \
	modules/cookiectl/contrib/print.c \
	modules/cookiectl/contrib/sockaddr.c \
	modules/cookiectl/print_pkt.c \
	modules/cookiectl/cookiectl.c
cookiectl_DEPEND := $(libkres)
cookiectl_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cookiectl)
