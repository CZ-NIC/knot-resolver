SUBDIRS = .

lib_LTLIBRARIES = libknotresolve.la

libknotresolve_la_SOURCES =		\
	layer/iterate.h	\
	layer/iterate.c	\
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

libknotresolve_la_CPPFLAGS = $(AM_CPPFLAGS) $(libknot_CFLAGS) $(libuv_CFLAGS)
libknotresolve_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_LIBS) $(libuv_LIBS)
