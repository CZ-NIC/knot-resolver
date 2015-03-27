# Preload libraries
preload_PATH := tests
ifeq ($(PLATFORM),Darwin)
	preload_LIBS := @DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(preload_PATH):${DYLD_LIBRARY_PATH}"
else
	preload_LIBS := @LD_LIBRARY_PATH="$(preload_PATH):${LD_LIBRARY_PATH}"
endif

# Unit tests
ifeq ($(HAS_cmocka), yes)
include tests.unit.mk
# Integration tests
ifeq ($(HAS_python), yes)
include tests.integration.mk
endif # HAS_python
endif # HAS_cmocka

# Targets
tests: check-unit check-integration
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) libmock_calls-clean _test_integration-clean

.PHONY: tests tests-clean
