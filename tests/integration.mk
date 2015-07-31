#
# Integration tests
#

CWRAP_PATH := $(socket_wrapper_LIBS)
FAKETIME_PATH := $(libfaketime_LIBS)

# Targets

ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(FAKETIME_PATH):$(CWRAP_PATH)"
else
	preload_syms := LD_PRELOAD="$(FAKETIME_PATH):$(CWRAP_PATH)"
endif

check-integration:
	$(call preload_LIBS) $(preload_syms) tests/test_integration.py tests/testdata

.PHONY: check-integration
