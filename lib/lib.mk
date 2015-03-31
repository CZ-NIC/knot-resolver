libkresolve_SOURCES := \
	lib/generic/map.c      \
	lib/layer/iterate.c    \
	lib/layer/itercache.c  \
	lib/utils.c            \
	lib/nsrep.c            \
	lib/module.c           \
	lib/resolve.c          \
	lib/zonecut.c          \
	lib/rplan.c            \
	lib/cache.c

libkresolve_HEADERS := \
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
libkresolve_DEPEND := 
libkresolve_LIBS := $(libknot_LIBS)
libkresolve_TARGET := -Wl,-rpath,lib -Llib -lkresolve

# Make library
$(eval $(call make_lib,libkresolve,lib))

# Targets
lib: $(libkresolve)
lib-install: libkresolve-install
lib-clean: libkresolve-clean

.PHONY: lib lib-install lib-clean
