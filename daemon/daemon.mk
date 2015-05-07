kresolved_SOURCES := \
	daemon/io.c          \
	daemon/network.c     \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/ffimodule.c   \
	daemon/main.c

# Embed resources
daemon/engine.o: daemon/lua/sandbox.inc daemon/lua/config.inc
%.inc: %.lua
	@$(call quiet,XXD,$<) -i - < $< > $@

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
