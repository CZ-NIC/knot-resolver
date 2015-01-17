if BUILD_DAEMON

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib \
	$(libuv_CFLAGS) \
	$(libknot_CFLAGS)

kresolved_SOURCES =					\
	layer/query.h					\
	layer/query.c					\
	udp.h							\
	udp.c							\
	tcp.h							\
	tcp.c							\
	worker.h						\
	worker.c						\
	main.c

# sbin programs
sbin_PROGRAMS = kresolved
kresolved_LDADD = $(top_builddir)/lib/libkresolve.la $(libuv_LIBS) $(libknot_LIBS)

endif
