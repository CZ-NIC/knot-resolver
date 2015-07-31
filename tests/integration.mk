#
# Integration tests
#

CWRAP_PATH := $(socket_wrapper_LIBS)
FAKETIME_PATH := $(libfaketime_LIBS)

# Targets
preload_syms := LD_PRELOAD="$(FAKETIME_PATH):$(CWRAP_PATH)"

check-integration: $(libmock_calls) $(_test_integration)
	$(call preload_LIBS) $(preload_syms) tests/test_integration.py tests/testdata

.PHONY: check-integration
