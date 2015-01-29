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

check_LTLIBRARIES = _test_integration.la
_test_integration_la_SOURCES = test_integration.c
_test_integration_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
_test_integration_la_LDFLAGS = $(LDFLAGS) -rpath $(abs_builddir) -module -shared -avoid-version --wrap=gettimeofday
_test_integration_la_LIBADD = $(top_builddir)/lib/libkresolve_static.la $(libknot_LIBS) $(PYTHON_LIBS)

convenience-link: $(check_LTLIBRARIES)
	@for soname in `echo | $(EGREP) "^dlname=" $(check_LTLIBRARIES) | $(SED) -e "s|^dlname='\(.*\)'|\1|"`; do  \
		rm -f $(abs_builddir)/$$soname; $(LN_S) $(abs_builddir)/.libs/$$soname $$soname || true;\
	done

check-local-integration: convenience-link
	@echo "---- Executing integration tests ----"
	@cd $(top_builddir)
	@$(top_builddir)/tests/test_integration.py testdata

clean-local:
	@for soname in `echo | $(EGREP) "^dlname=" $(check_LTLIBRARIES) | $(SED) -e "s|^dlname='\(.*\)'|\1|"`; do  \
		test -L $(abs_builddir)/$$soname && rm -f $(abs_builddir)/$$soname || true; \
	done
else

check-local-integration:

endif

check-local: check-local-exec check-local-integration
