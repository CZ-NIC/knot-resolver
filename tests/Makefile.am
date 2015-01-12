# Unit tests
if BUILD_TESTS

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/lib \
	$(libknot_CFLAGS) \
	$(cmocka_CFLAGS)

LDADD = \
	$(top_builddir)/lib/libknotresolve.la \
	$(libknot_LIBS) \
	$(cmocka_LIBS)


check_PROGRAMS = \
	test_cache \
	test_context \
	test_resolve

check-compile-only: $(check_PROGRAMS)
check-local-exec: $(check_PROGRAMS)
	@echo "---- Executing unit tests ----"
	$(top_builddir)/tests/runtests -b $(top_builddir)/tests $(check_PROGRAMS)

endif

# Integration tests
if BUILD_INTEGRATION

noinst_LTLIBRARIES = _test_integration.la
_test_integration_la_SOURCES = test_integration.c
_test_integration_la_CPPFLAGS = $(PYTHON_CPPFLAGS) $(AM_CPPFLAGS)
_test_integration_la_LDFLAGS = -rpath $(abs_builddir) -module -export-dynamic -shared -avoid-version \
                               --wrap=gettimeofday $(PYTHON_LDFLAGS)
_test_integration_la_LIBADD = $(LDADD)

convenience-link: $(noinst_LTLIBRARIES)
	@for soname in `echo | $(EGREP) "^dlname=" $(noinst_LTLIBRARIES) | $(SED) -e "s|^dlname='\(.*\)'|\1|"`; do  \
		rm -f $(abs_builddir)/$$soname; $(LN_S) $(abs_builddir)/.libs/$$soname $$soname || true;\
	done

check-local-integration: convenience-link
	@echo "---- Executing integration tests ----"
	@$(LIBTOOL) --mode=execute -dlopen $(top_builddir)/lib/libknotresolve.la ./test_integration.py testdata

clean-local:
	@for soname in `echo | $(EGREP) "^dlname=" $(noinst_LTLIBRARIES) | $(SED) -e "s|^dlname='\(.*\)'|\1|"`; do  \
		test -L $(abs_builddir)/$$soname && rm -f $(abs_builddir)/$$soname || true; \
	done

endif

check-local: check-local-exec check-local-integration
