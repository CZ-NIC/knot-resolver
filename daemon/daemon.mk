kresd_EMBED := \
	contrib/ccan/asprintf/asprintf.c
kresd_SOURCES := \
	$(kresd_EMBED)   \
	daemon/io.c          \
	daemon/network.c     \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/ffimodule.c   \
	daemon/main.c
kresd_DIST := daemon/lua/kres.lua daemon/lua/trust_anchors.lua

# Embedded resources
%.inc: %.lua
	@$(call quiet,XXD,$<) $< > $@
ifeq ($(AMALG), yes)
kresd.amalg.c: daemon/lua/sandbox.inc daemon/lua/config.inc
else
daemon/engine.o: daemon/lua/sandbox.inc daemon/lua/config.inc
endif

# Installed FFI bindings
bindings-install: $(kresd_DIST) moduledir
	$(INSTALL) -m 0644 $(kresd_DIST) $(MODULEDIR)

kresd_DEPEND := $(libkres)
kresd_LIBS := $(libkres_TARGET) $(libknot_LIBS) $(libdnssec_LIBS) $(libuv_LIBS) $(lua_LIBS)

# Make binary
ifeq ($(HAS_lua)|$(HAS_libuv), yes|yes)
$(eval $(call make_bin,kresd,daemon,yes))
endif

# Targets
daemon: $(kresd)
daemon-install: kresd-install bindings-install
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc

.PHONY: daemon daemon-install daemon-clean
