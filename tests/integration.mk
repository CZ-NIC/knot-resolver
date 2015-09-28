#
# Integration tests
#

TESTS ?= tests/testdata
CWRAP_PATH := $(strip $(socket_wrapper_LIBS))

# Targets
libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime):$(CWRAP_PATH)"
else
	preload_syms := LD_PRELOAD="$(libfaketime):$(CWRAP_PATH)"
endif

# Synchronize submodules
$(libfaketime_DIR):
	@git submodule init
$(libfaketime_DIR)/Makefile: $(libfaketime_DIR)
	@git submodule update
# Build libfaketime contrib
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="" $(MAKE) -C $(libfaketime_DIR)

check-integration: $(libfaketime)
	@$(preload_LIBS) $(preload_syms) python tests/test_integration.py $(TESTS) $(abspath daemon/kresd) ./kresd.j2 config

.PHONY: check-integration
