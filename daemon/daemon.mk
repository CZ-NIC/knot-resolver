kresd_EMBED := \
	contrib/ccan/json/json.c
kresd_SOURCES := \
	$(kresd_EMBED)   \
	daemon/io.c          \
	daemon/network.c     \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/ffimodule.c   \
	daemon/bindings/kres.c \
	daemon/main.c

# Embed resources
daemon/engine.o: daemon/lua/sandbox.inc daemon/lua/config.inc
%.inc: %.lua
	@$(call quiet,XXD,$<) $< > $@

# Dependencies
kresd_DEPEND := $(libkres)
kresd_LIBS := $(libkres_TARGET) $(libknot_LIBS) $(libuv_LIBS) $(lua_LIBS)

# Make binary
ifeq ($(HAS_lua)|$(HAS_libuv), yes|yes)
$(eval $(call make_bin,kresd,daemon))
endif

# Targets
daemon: $(kresd)
daemon-install: kresd-install
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc

.PHONY: daemon daemon-install daemon-clean
