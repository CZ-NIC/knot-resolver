AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib

sbin_PROGRAMS = kresolved 

kresolved_SOURCES =					\
	layer/query.h					\
	layer/query.c					\
	worker.h						\
	worker.c						\
	main.c

# sbin programs
kresolved_LDADD = $(top_builddir)/lib/libknotresolve.la \
					$(KNOT_LIBS) \
					$(libuv_LIBS)
