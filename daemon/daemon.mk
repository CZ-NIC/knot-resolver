kresd_SOURCES := \
	daemon/io.c          \
	daemon/network.c     \
	daemon/engine.c      \
	daemon/worker.c      \
	daemon/bindings.c    \
	daemon/ffimodule.c   \
	daemon/tls.c         \
	daemon/tls_ephemeral_credentials.c \
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
endif

# Installed FFI bindings
bindings-install: $(kresd_DIST) $(DESTDIR)$(MODULEDIR)
	$(INSTALL) -m 0644 $(kresd_DIST) $(DESTDIR)$(MODULEDIR)

LUA_HAS_SETFUNCS := \
	$(shell pkg-config luajit --atleast-version=2.1.0-beta3 && echo 1 || echo 0)

kresd_CFLAGS := -fPIE \
		-Dlibknot_SONAME=\"$(libknot_SONAME)\" \
		-Dlibzscanner_SONAME=\"$(libzscanner_SONAME)\" \
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
date := $(shell date +%F -r NEWS)
daemon: $(kresd) $(kresd_DIST)
daemon-install: kresd-install bindings-install
ifneq ($(SED),)
	$(SED) -e "s/@VERSION@/$(VERSION)/" -e "s/@DATE@/$(date)/" \
		-e "s|@MODULEDIR@|$(MODULEDIR)|" \
		doc/kresd.8.in > doc/kresd.8
	$(INSTALL) -d -m 0755 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 0644 doc/kresd.8 $(DESTDIR)$(MANDIR)/man8/
endif
daemon-clean: kresd-clean
	@$(RM) daemon/lua/*.inc daemon/lua/kres.lua daemon/lua/trust_anchors.lua \
		daemon/lua/zonefile.lua daemon/lua/config.lua

KNOT_RRSET_TXT_DUMP := \
	$(shell pkg-config libknot --atleast-version=2.4.0 && echo true || echo false)
daemon/lua/kres.lua: daemon/lua/kres.lua.in
	@$(call quiet,SED,$<) -e "s|@KNOT_RRSET_TXT_DUMP@|$(KNOT_RRSET_TXT_DUMP)|g" $< > $@

daemon/lua/trust_anchors.lua: daemon/lua/trust_anchors.lua.in
	@$(call quiet,SED,$<) -e "s|@ETCDIR@|$(ETCDIR)|g" $< > $@

daemon/lua/config.lua: daemon/lua/config.lua.in
	@$(call quiet,SED,$<) -e "s|@ROOTHINTS@|$(ROOTHINTS)|g" $< > $@

LIBZSCANNER_COMMENTS := \
	$(shell pkg-config libzscanner --atleast-version=2.4.2 && echo true || echo false)
daemon/lua/zonefile.lua: daemon/lua/zonefile.lua.in
	@$(call quiet,SED,$<) -e "s|@LIBZSCANNER_COMMENTS@|$(LIBZSCANNER_COMMENTS)|g" $< > $@

daemon/lua/kres-gen.lua: | $(libkres)
	@echo "WARNING: regenerating $@"
	@# the sed saves some space(s)
	daemon/lua/kres-gen.sh | sed 's/    /\t/g' > $@
.DELETE_ON_ERROR: daemon/lua/kres-gen.lua

# Client
ifeq ($(HAS_libedit), yes)
kresc_SOURCES := daemon/kresc.c
kresc_CFLAGS += -fPIE $(libedit_CFLAGS)
kresc_LIBS += $(contrib_TARGET) $(libedit_LIBS)
kresc_DEPEND := $(libkres) $(contrib)
$(eval $(call make_sbin,kresc,daemon,yes))
client: $(kresc)
client-install: kresc-install
client-clean: kresc-clean
endif

.PHONY: daemon daemon-install daemon-clean client client-install client-clean
