cookies_CFLAGS := -fvisibility=hidden -fPIC
# Compat with libknot < 2.4; the identifier got renamed since 2.4.0.
cookies_CFLAGS += $(shell pkg-config --atleast-version=2.4.0 libknot \
				    || echo -Dknot_pkt_ext_rcode=knot_pkt_get_ext_rcode)

cookies_SOURCES := \
	modules/cookies/cookiectl.c \
	modules/cookies/cookiemonster.c \
	modules/cookies/cookies.c
cookies_DEPEND := $(libkres)
cookies_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,cookies)
