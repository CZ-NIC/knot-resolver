kresolved_SOURCES := \
	daemon/layer/query.c \
	daemon/udp.c         \
	daemon/tcp.c         \
	daemon/cmd.c         \
	daemon/worker.c      \
	daemon/main.c

# Dependencies
kresolved_DEPEND := libkresolve libknot libuv
kresolved_LIBS := $(libkresolve_TARGET) $(libknot_LIBS) $(libuv_LIBS)

# Make binary
$(eval $(call make_bin,kresolved,daemon))
