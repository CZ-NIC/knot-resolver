kresolved_SOURCES := \
	daemon/layer/query.c \
	daemon/udp.c         \
	daemon/tcp.c         \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/main.c

# Embed resources
daemon/engine.o: daemon/lua/init.inc daemon/lua/config.inc
%.inc: %.lua
	@$(call quiet,XXD,$<) -i < $< > $@
	@echo ', 0x00' >> $@

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
	@$(RM) daemon/lua/*.inc

.PHONY: daemon daemon-install daemon-clean
