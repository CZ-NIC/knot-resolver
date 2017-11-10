libkres_SOURCES := \
	lib/generic/lru.c      \
	lib/generic/map.c      \
	lib/layer/iterate.c    \
	lib/layer/validate.c   \
	lib/layer/cache_lmdb.c \
	lib/dnssec/nsec.c      \
	lib/dnssec/nsec3.c     \
	lib/dnssec/signature.c \
	lib/dnssec/ta.c        \
	lib/dnssec.c           \
	lib/utils.c            \
	lib/nsrep.c            \
	lib/module.c           \
	lib/resolve.c          \
	lib/zonecut.c          \
	lib/rplan.c            \
	lib/cache.c            \
	lib/cache/entry_list.c \
	lib/cache/entry_pkt.c  \
	lib/cache/entry_rr.c   \
	lib/cache/knot_pkt.c   \
	lib/cdb_lmdb.c

libkres_HEADERS := \
	lib/generic/array.h    \
	lib/generic/lru.h      \
	lib/generic/map.h      \
	lib/generic/set.h      \
	lib/layer.h            \
	lib/dnssec/nsec.h      \
	lib/dnssec/nsec3.h     \
	lib/dnssec/signature.h \
	lib/dnssec/ta.h        \
	lib/dnssec.h           \
	lib/utils.h            \
	lib/nsrep.h            \
	lib/module.h           \
	lib/resolve.h          \
	lib/zonecut.h          \
	lib/rplan.h            \
	lib/cache.h            \
	lib/cdb.h              \
	lib/cdb_lmdb.h

# Dependencies
libkres_DEPEND := $(contrib)
libkres_CFLAGS := -fvisibility=hidden -fPIC $(lmdb_CFLAGS)
libkres_LIBS := $(contrib_TARGET) $(libknot_LIBS) $(libdnssec_LIBS) $(lmdb_LIBS) \
				$(libuv_LIBS) $(gnutls_LIBS)
libkres_TARGET := -L$(abspath lib) -lkres

ifeq ($(ENABLE_COOKIES),yes)
libkres_SOURCES += \
	lib/cookies/alg_containers.c \
	lib/cookies/alg_sha.c \
	lib/cookies/helper.c \
	lib/cookies/lru_cache.c \
	lib/cookies/nonce.c

libkres_HEADERS += \
	lib/cookies/alg_containers.h \
	lib/cookies/alg_sha.h \
	lib/cookies/control.h \
	lib/cookies/helper.h \
	lib/cookies/lru_cache.h \
	lib/cookies/nonce.h

libkres_LIBS += $(nettle_LIBS)
endif

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
	@echo 'URL: https://www.knot-resolver.cz' >> $@
	@echo 'Version: $(VERSION)' >> $@
	@echo 'Libs: -L$${libdir} -lkres' >> $@
	@echo 'Cflags: -I$${includedir}' >> $@
libkres-pcinstall: libkres.pc libkres-install
	$(INSTALL) -d -m 755 $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL)    -m 644 $< $(DESTDIR)$(PKGCONFIGDIR)

# Targets
lib: $(libkres)
lib-install: libkres-install libkres-pcinstall
lib-clean: libkres-clean

.PHONY: lib lib-install lib-clean libkres.pc
