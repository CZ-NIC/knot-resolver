#
# Integration tests
#
CWRAP_PATH := $(shell pkg-config --libs socket_wrapper)
# TODO: find this in ld search paths
# TODO: this requires newer version than is in the Debian to support FAKETIME_TIMESTAMP_FILE
# TODO: maybe we can bundle it (it's small enough)
FAKETIME_PATH := $(wildcard ~/.local/lib/faketime/libfaketime.so.1)

# Targets
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(FAKETIME_PATH):$(CWRAP_PATH)"
else
	preload_syms := LD_PRELOAD="$(FAKETIME_PATH):$(CWRAP_PATH)"
endif

check-integration:
	$(call preload_LIBS) $(preload_syms) tests/test_integration.py tests/testdata

.PHONY: check-integration
