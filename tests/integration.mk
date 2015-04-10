#
# Integration tests
#

# Mocked calls library
libmock_calls_SOURCES := tests/mock_calls.c
libmock_calls_LIBS := $(tests_LIBS) $(python_LIBS)
libmock_calls_DEPEND := $(libkresolve)
$(eval $(call make_lib,libmock_calls,tests))

# Python module for tests
_test_integration_SOURCES := tests/test_integration.c
_test_integration_LIBS := -Ltests -lmock_calls $(libmock_calls_LIBS)
_test_integration_DEPEND := $(libmock_calls)
$(eval $(call make_shared,_test_integration,tests))

# Targets
check-integration: $(libmock_calls) $(_test_integration)
	$(call preload_LIBS) tests/test_integration.py tests/testdata

.PHONY: check-integration
