kresolved_SOURCES := \
	daemon/layer/query.c \
	daemon/udp.c         \
	daemon/tcp.c         \
	daemon/cmd.c         \
	daemon/worker.c      \
	daemon/main.c

# Dependencies
kresolved_DEPEND := $(libkresolve)
kresolved_LIBS := $(libkresolve_TARGET) $(libknot_LIBS) $(libuv_LIBS) $(lua_LIBS)

# Make binary
ifeq ($(HAS_lua)|$(HAS_libuv), yes|yes)
$(eval $(call make_bin,kresolved,daemon))
endif

# Targets
daemon: $(kresolved)
daemon-install: kresolved-install
daemon-clean: kresolved-clean
.PHONY: daemon daemon-install daemon-clean
