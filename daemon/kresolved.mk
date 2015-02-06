kresolved_SOURCES := \
	daemon/layer/query.c \
	daemon/udp.c         \
	daemon/tcp.c         \
	daemon/worker.c      \
	daemon/main.c

# Dependencies
kresolved_DEPEND := libkresolve libknot libuv
kresolved_LIBS := $(libkresolve_TARGET) $(libuv_LIBS) $(libknot_LIBS)

# Make binary
$(eval $(call make_bin,kresolved,daemon))