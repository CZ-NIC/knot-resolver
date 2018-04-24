kresd_SOURCES := \
	daemon/io.c          \
	daemon/network.c     \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/ffimodule.c   \
	daemon/tls.c         \
	daemon/tls_ephemeral_credentials.c \
	daemon/zimport.c     \
	daemon/main.c

kresd_DIST := daemon/lua/kres.lua daemon/lua/kres-gen.lua \
              daemon/lua/trust_anchors.lua daemon/lua/zonefile.lua

# Embedded resources
%.inc: %.lua
	@$(call quiet,XXD_LUA,$<) $< > $@
ifeq ($(AMALG), yes)
kresd.amalg.c: daemon/lua/sandbox.inc daemon/lua/config.inc
else
daemon/engine.o: daemon/lua/sandbox.inc daemon/lua/config.inc
kresd-lint: daemon/lua/sandbox.inc daemon/lua/config.inc
endif

# Installed FFI bindings
bindings-install: $(kresd_DIST) $(DESTDIR)$(MODULEDIR)
	$(INSTALL) -m 0644 $(kresd_DIST) $(DESTDIR)$(MODULEDIR)

LUA_HAS_SETFUNCS := \
	$(shell pkg-config luajit --atleast-version=2.1.0-beta3 && echo 1 || echo 0)

kresd_CFLAGS := -fPIE \
		-Dlibknot_SONAME=\"$(libknot_SONAME)\" \
		-Dlibzscanner_SONAME=\"$(libzscanner_SONAME)\" \
		-DROOTHINTS=\"$(ROOTHINTS)\" \
		-DLIBEXT=\"$(LIBEXT)\" \
		-DLUA_HAS_SETFUNCS="$(LUA_HAS_SETFUNCS)"
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
$(eval $(call make_sbin,kresd,daemon,yes))

# Targets
date := $(shell date -r NEWS +%F)
daemon: $(kresd) $(kresd_DIST)
daemon-install: kresd-install bindings-install
ifneq ($(SED),)
	$(SED) -e "s/@VERSION@/$(VERSION)/" -e "s/@DATE@/$(date)/" \
		-e "s|@MODULEDIR@|$(MODULEDIR)|" \
		-e "s|@KEYFILE_DEFAULT@|$(KEYFILE_DEFAULT)|" \
		doc/kresd.8.in > doc/kresd.8
	$(INSTALL) -d -m 0755 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 0644 doc/kresd.8 $(DESTDIR)$(MANDIR)/man8/
endif
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc daemon/lua/trust_anchors.lua \
		daemon/lua/zonefile.lua

daemon/lua/trust_anchors.lua: daemon/lua/trust_anchors.lua.in
	@$(call quiet,SED,$<) -e "s|@ETCDIR@|$(ETCDIR)|g;s|@KEYFILE_DEFAULT@|$(KEYFILE_DEFAULT)|g" $< > $@

LIBZSCANNER_COMMENTS := \
	$(shell pkg-config libzscanner --atleast-version=2.4.2 && echo true || echo false)
daemon/lua/zonefile.lua: daemon/lua/zonefile.lua.in
	@$(call quiet,SED,$<) -e "s|@LIBZSCANNER_COMMENTS@|$(LIBZSCANNER_COMMENTS)|g" $< > $@

daemon/lua/kres-gen.lua: | $(libkres)
	@echo "WARNING: regenerating $@"
	@# the sed saves some space(s)
	daemon/lua/kres-gen.sh | sed 's/    /\t/g' > $@
.DELETE_ON_ERROR: daemon/lua/kres-gen.lua

.PHONY: daemon daemon-install daemon-clean
