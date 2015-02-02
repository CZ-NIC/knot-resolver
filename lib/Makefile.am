# Static version of the library
noinst_LTLIBRARIES = libkresolve_static.la
libkresolve_static_la_CPPFLAGS = $(AM_CPPFLAGS) $(libknot_CFLAGS) $(libuv_CFLAGS)
libkresolve_static_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_LIBS) $(libuv_LIBS)
libkresolve_static_la_SOURCES =		\
	layer/iterate.h	\
	layer/iterate.c	\
	layer/itercache.h	\
	layer/itercache.c	\
	layer/static.h	\
	layer/static.c	\
	layer/stats.h	\
	layer/stats.c	\
	layer.h			\
	context.h 		\
	context.c 		\
	resolve.h 		\
	resolve.c		\
	zonecut.h		\
	zonecut.c		\
	rplan.h			\
	rplan.c			\
	cache.h			\
	cache.c

# Shared version (to be installed)
lib_LTLIBRARIES = libkresolve.la
libkresolve_la_SOURCES = 
libkresolve_la_LIBADD = libkresolve_static.la
