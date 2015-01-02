AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib \
	$(libuv_CFLAGS) \
	$(libknot_CFLAGS)

sbin_PROGRAMS = kresolved

kresolved_SOURCES =					\
	layer/query.h					\
	layer/query.c					\
	worker.h						\
	worker.c						\
	main.c

# sbin programs
kresolved_LDADD = $(top_builddir)/lib/libknotresolve.la $(libuv_LIBS) $(libknot_LIBS)
