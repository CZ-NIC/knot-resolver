ccan_EMBED := \
	contrib/ccan/ilog/ilog.c \
	contrib/ccan/isaac/isaac.c \
	contrib/ucw/mempool.c \
	contrib/murmurhash3/murmurhash3.c

libkres_SOURCES := \
	$(ccan_EMBED)          \
	lib/generic/map.c      \
	lib/layer/iterate.c    \
	lib/layer/rrcache.c    \
	lib/layer/rrsigcache.c \
	lib/layer/pktcache.c   \
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
	lib/utils.h            \
	lib/nsrep.h            \
	lib/module.h           \
	lib/resolve.h          \
	lib/zonecut.h          \
	lib/rplan.h            \
	lib/cache.h

# Dependencies
libkres_DEPEND := 
libkres_LIBS := $(libknot_LIBS)
libkres_TARGET := -Wl,-rpath,lib -Llib -lkres

# Make library
$(eval $(call make_static,libkres,lib))

# Targets
lib: $(libkres)
lib-install: libkres-install
lib-clean: libkres-clean

.PHONY: lib lib-install lib-clean
