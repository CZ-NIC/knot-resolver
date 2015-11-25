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

# Embed resources
ifeq ($(AMALG), yes)
kresd.amalg.c: daemon/lua/sandbox.inc daemon/lua/config.inc
else
daemon/engine.o: daemon/lua/sandbox.inc daemon/lua/config.inc
endif
%.inc: %.lua
	@$(call quiet,XXD,$<) $< > $@
# Installed FFI bindings
bindings-install: daemon/lua/kres.lua daemon/lua/trust_anchors.lua
	$(INSTALL) -d $(PREFIX)/$(MODULEDIR)
	$(INSTALL) -m 0644 $^ $(PREFIX)/$(MODULEDIR)

kresd_DEPEND := $(libkres)
kresd_LIBS := $(libkres_TARGET) $(libknot_LIBS) $(libdnssec_LIBS) $(libuv_LIBS) $(lua_LIBS)

# Make binary
ifeq ($(HAS_lua)|$(HAS_libuv), yes|yes)
$(eval $(call make_bin,kresd,daemon))
endif

# Targets
daemon: $(kresd)
daemon-install: kresd-install bindings-install
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc

.PHONY: daemon daemon-install daemon-clean
