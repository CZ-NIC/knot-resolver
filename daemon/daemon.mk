kresd_SOURCES := \
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
bindings-install: $(kresd_DIST) $(DESTDIR)$(MODULEDIR)
	$(INSTALL) -m 0644 $(kresd_DIST) $(DESTDIR)$(MODULEDIR)

kresd_CFLAGS := -fPIE
kresd_DEPEND := $(libkres) $(contrib)
kresd_LIBS := $(libkres_TARGET) $(contrib_TARGET) $(libknot_LIBS) \
              $(libzscanner_LIBS) $(libdnssec_LIBS) $(libuv_LIBS) $(lua_LIBS) \
              $(gnutls_LIBS)

# Enable systemd
ifeq ($(HAS_libsystemd), yes)
kresd_CFLAGS += -DHAS_SYSTEMD
kresd_LIBS += $(libsystemd_LIBS)
endif

# Make binary
ifeq ($(HAS_lua)|$(HAS_libuv), yes|yes)
$(eval $(call make_sbin,kresd,daemon,yes))
endif

# Targets
date := $(shell date +%F)
daemon: $(kresd)
daemon-install: kresd-install bindings-install
ifneq ($(SED),)
	$(SED) -e "s/@VERSION@/$(MAJOR).$(MINOR).$(PATCH)/" -e "s/@DATE@/$(date)/" doc/kresd.8.in > doc/kresd.8
	$(INSTALL) -d -m 0755 $(DESTDIR)$(PREFIX)/share/man/man8/
	$(INSTALL) -m 0644 doc/kresd.8 $(DESTDIR)$(PREFIX)/share/man/man8/
endif
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc

.PHONY: daemon daemon-install daemon-clean
