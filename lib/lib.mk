libkres_SOURCES := \
	lib/cache/api.c \
	lib/cache/cdb_lmdb.c \
	lib/cache/entry_list.c \
	lib/cache/entry_pkt.c \
	lib/cache/entry_rr.c \
	lib/cache/knot_pkt.c \
	lib/cache/nsec1.c \
	lib/cache/nsec3.c \
	lib/cache/peek.c \
	lib/dnssec.c \
	lib/dnssec/nsec.c \
	lib/dnssec/nsec3.c \
	lib/dnssec/signature.c \
	lib/dnssec/ta.c \
	lib/generic/lru.c \
	lib/generic/map.c \
	lib/generic/queue.c \
	lib/generic/trie.c \
	lib/layer/cache.c \
	lib/layer/iterate.c \
	lib/layer/validate.c \
	lib/module.c \
	lib/nsrep.c \
	lib/resolve.c \
	lib/rplan.c \
	lib/utils.c \
	lib/zonecut.c

libkres_HEADERS := \
	lib/cache/api.h \
	lib/cache/cdb_api.h \
	lib/cache/cdb_lmdb.h \
	lib/cache/impl.h \
	lib/defines.h \
	lib/dnssec.h \
	lib/dnssec/nsec.h \
	lib/dnssec/nsec3.h \
	lib/dnssec/signature.h \
	lib/dnssec/ta.h \
	lib/generic/array.h \
	lib/generic/lru.h \
	lib/generic/map.h \
	lib/generic/pack.h \
	lib/generic/queue.h \
	lib/generic/trie.h \
	lib/layer.h \
	lib/layer/iterate.h \
	lib/module.h \
	lib/nsrep.h \
	lib/resolve.h \
	lib/rplan.h \
	lib/utils.h \
	lib/zonecut.h

# Dependencies
libkres_DEPEND := $(contrib)
libkres_CFLAGS := -fPIC $(lmdb_CFLAGS)
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
	@echo 'Description: Knot Resolver library' >> $@
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
