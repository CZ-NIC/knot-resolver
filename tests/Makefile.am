AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib \
	$(libknot_CFLAGS) \
	$(cmocka_CFLAGS)

LDADD = \
	$(top_builddir)/lib/libkresolve_static.la \
	$(libknot_LIBS) \
	$(cmocka_LIBS)

# Unit tests
if BUILD_TESTS

check_PROGRAMS = \
	test_context \
	test_rplan \
	test_cache \
	test_resolve

check-compile-only: $(check_PROGRAMS)
check-local-exec: $(check_PROGRAMS)
	@echo "---- Executing unit tests ----"
	@cd $(top_builddir)
	$(top_builddir)/tests/runtests -b $(top_builddir)/tests $(check_PROGRAMS)

else

check-local-exec:

endif

# Integration tests
if BUILD_INTEGRATION

check_LTLIBRARIES = libmock_calls.la _test_integration.la

libmock_calls_la_SOURCES = mock_calls.c
libmock_calls_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
libmock_calls_la_LDFLAGS = $(LDFLAGS) -rpath $(abs_builddir)/tests -shared -avoid-version
libmock_calls_la_LIBADD = $(libknot_LIBS) $(top_builddir)/lib/libkresolve_static.la $(PYTHON_LIBS)

_test_integration_la_SOURCES = test_integration.c
_test_integration_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
_test_integration_la_LDFLAGS = $(LDFLAGS) -rpath $(abs_builddir) -module -shared -avoid-version
_test_integration_la_LIBADD = libmock_calls.la $(PYTHON_LIBS)

check_cmd = $(abs_builddir)/test_integration.py testdata

convenience-link: $(check_LTLIBRARIES)
	for soname in `echo | $(EGREP) "^dlname=" $(check_LTLIBRARIES) | $(SED) -e "s|\(.*\)dlname='\(.*\)'|\2|"`; do  \
		rm -f $(abs_builddir)/$$soname; $(LN_S) $(abs_builddir)/.libs/$$soname $$soname || true;\
	done

check-local-integration: convenience-link
	@echo "---- Executing integration tests ----"
if HOST_DARWIN
	@DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH=$(abs_builddir)/.libs DYLD_INSERT_LIBRARIES=$(abs_builddir)/.libs/libmock_calls.dylib $(check_cmd)
else
	@LD_PRELOAD=$(abs_builddir)/.libs/libmock_calls.so $(check_cmd)
endif

clean-local:
	rm -f *.so *.dylib || true
else

check-local-integration:

endif

check-local: check-local-exec check-local-integration
