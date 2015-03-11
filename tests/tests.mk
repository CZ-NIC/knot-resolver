#
# Unit tests
#

tests_BIN := \
	test_utils \
	test_module \
	test_context \
	test_rplan \
	test_cache \
	test_resolve

# Mock modules
mock_cmodule_SOURCES := tests/mock_cmodule.c
$(eval $(call make_lib,mock_cmodule,tests))
mock_gomodule_SOURCES := tests/mock_gomodule.c
$(eval $(call make_lib,mock_gomodule,tests))

# Dependencies
tests_DEPEND := libkresolve cmocka mock_cmodule mock_gomodule
tests_LIBS :=  $(libkresolve_TARGET) $(libkresolve_LIBS) $(cmocka_LIBS)

# Make test binaries
define make_test
$(1)_SOURCES := tests/$(1).c
$(1)_LIBS := $(tests_LIBS)
$(1)_DEPEND := $(tests_DEPEND)
$(call make_bin,$(1),tests)
endef

$(foreach test,$(tests_BIN),$(eval $(call make_test,$(test))))

#
# Integration tests
#

# Mocked calls library
libmock_calls_SOURCES := tests/mock_calls.c
libmock_calls_LIBS := $(tests_LIBS) $(python_LIBS)
libmock_calls_DEPEND := libkresolve
$(eval $(call make_lib,libmock_calls,tests))

# Python module for tests
_test_integration_SOURCES := tests/test_integration.c
_test_integration_LIBS := -Wl,-rpath,tests -Ltests -lmock_calls $(libmock_calls_LIBS)
_test_integration_DEPEND := libmock_calls
$(eval $(call make_shared,_test_integration,tests))

# Preload mock library
preload_PATH := tests
ifeq ($(PLATFORM),Darwin)
	preload_LIBS := @DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(preload_PATH):${DYLD_LIBRARY_PATH}"
else
	preload_LIBS := @LD_LIBRARY_PATH="$(preload_PATH):${LD_LIBRARY_PATH}"
endif

# Targets
.PHONY: check-integration check-unit tests tests-clean
check-integration: libmock_calls _test_integration
	$(call preload_LIBS) tests/test_integration.py tests/testdata
check-unit: $(tests_BIN)
	$(call preload_LIBS) tests/runtests -b tests $^
tests: check-unit check-integration
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) libmock_calls-clean _test_integration-clean
