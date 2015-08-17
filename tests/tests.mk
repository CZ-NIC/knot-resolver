# Preload libraries
preload_PATH := $(abspath contrib/libfaketime/src)
ifeq ($(PLATFORM),Darwin)
	preload_LIBS := @DYLD_FORCE_FLAT_NAMESPACE=1 \
	                DYLD_LIBRARY_PATH="$(preload_PATH):${DYLD_LIBRARY_PATH}"
else
	preload_LIBS := @LD_LIBRARY_PATH="$(preload_PATH):${LD_LIBRARY_PATH}"
endif

# Unit tests
ifeq ($(HAS_cmocka), yes)
include tests/unit.mk
else
$(warning cmocka not found, skipping unit tests)
endif

# Integration tests
ifeq ($(HAS_python)|$(HAS_socket_wrapper), yes|yes)
include tests/integration.mk
else
$(warning python or socket_wrapper not found, skipping integration tests)
endif

# Targets
tests: check-unit check-integration
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean)

.PHONY: tests tests-clean
