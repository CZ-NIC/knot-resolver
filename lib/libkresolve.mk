libkresolve_SOURCES := \
	lib/layer/iterate.c    \
	lib/layer/itercache.c  \
	lib/layer/static.c     \
	lib/layer/stats.c      \
	lib/context.c          \
	lib/resolve.c          \
	lib/zonecut.c          \
	lib/rplan.c            \
	lib/cache.c

libkresolve_HEADERS := \
	lib/layer/iterate.h    \
	lib/layer/itercache.h  \
	lib/layer/static.h     \
	lib/layer/stats.h      \
	lib/layer.h            \
	lib/context.h          \
	lib/resolve.h          \
	lib/zonecut.h          \
	lib/rplan.h            \
	lib/cache.h

# Dependencies
libkresolve_DEPEND := libknot
libkresolve_LIBS := $(libknot_LIBS)
libkresolve_TARGET := -Wl,-rpath,lib -Llib -lkresolve

# Make library
$(eval $(call make_lib,libkresolve,lib))