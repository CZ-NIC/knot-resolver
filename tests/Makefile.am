if BUILD_TESTS

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib

LDADD = \
	$(top_builddir)/lib/libknotresolve.la \
	$(libuv_LIBS) \
	$(libknot_LIBS) \
	$(cmocka_LIBS)

check_PROGRAMS = \
	test_cache \
	test_context \
	test_resolve

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/tests/runtests -b $(top_builddir)/tests $(check_PROGRAMS)

endif
