libkres_SOURCES := \
	lib/generic/map.c      \
	lib/layer/iterate.c    \
	lib/layer/validate.c   \
	lib/layer/rrcache.c    \
	lib/layer/pktcache.c   \
	lib/dnssec/nsec.c      \
	lib/dnssec/nsec3.c     \
	lib/dnssec/packet/pkt.c \
	lib/dnssec/signature.c \
	lib/dnssec/ta.c        \
	lib/dnssec.c           \
	lib/utils.c            \
	lib/nsrep.c            \
	lib/module.c           \
	lib/resolve.c          \
	lib/zonecut.c          \
	lib/rplan.c            \
	lib/cache.c

libkres_HEADERS := \
	lib/generic/array.h    \
	lib/generic/map.h      \
	lib/generic/set.h      \
	lib/layer.h            \
	lib/dnssec/nsec.h      \
	lib/dnssec/nsec3.h     \
	lib/dnssec/packet/pkt.h \
	lib/dnssec/rrtype/ds.h \
	lib/dnssec/signature.h \
	lib/dnssec/ta.h        \
	lib/dnssec.h           \
	lib/utils.h            \
	lib/nsrep.h            \
	lib/module.h           \
	lib/resolve.h          \
	lib/zonecut.h          \
	lib/rplan.h            \
	lib/cache.h

# Dependencies
libkres_DEPEND := $(contrib)
libkres_CFLAGS := -fvisibility=hidden -fPIC
libkres_LDFLAGS := -fvisibility=hidden -fPIC
libkres_LIBS := $(contrib_TARGET) $(libknot_LIBS) $(libdnssec_LIBS)
libkres_TARGET := -L$(abspath lib) -lkres

# Make library
ifeq ($(BUILDMODE), static)
$(eval $(call make_static,libkres,lib,yes))
else
$(eval $(call make_lib,libkres,lib,yes,$(ABIVER)))
endif

# Generate pkg-config file
libkres.pc:
	@echo 'prefix='$(PREFIX) > $@
	@echo 'exec_prefix=$${prefix}' >> $@
	@echo 'libdir='$(LIBDIR) >> $@
	@echo 'includedir='$(INCLUDEDIR) >> $@
	@echo 'Name: libkres' >> $@
	@echo 'Description: Knot DNS Resolver library' >> $@
	@echo 'URL: https://www.knot-dns.cz' >> $@
	@echo 'Version: $(MAJOR).$(MINOR).$(PATCH)' >> $@
	@echo 'Libs: -L$${libdir} -lkres' >> $@
	@echo 'Cflags: -I$${includedir}' >> $@
libkres-pcinstall: libkres.pc libkres-install
	$(INSTALL) -d -m 755 $(DESTDIR)$(LIBDIR)/pkgconfig/
	$(INSTALL)    -m 644 $< $(DESTDIR)$(LIBDIR)/pkgconfig/

# Targets
lib: $(libkres)
lib-install: libkres-install libkres-pcinstall
lib-clean: libkres-clean

.PHONY: lib lib-install lib-clean libkres.pc
