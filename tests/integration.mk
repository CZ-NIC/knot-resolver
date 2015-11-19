#
# Integration tests
#

# Path to scenario files
TESTS=tests/integration/sets/resolver
# Path to daemon
DAEMON=kresd
# Template file name
TEMPLATE=template/kresd.j2
# Config file name
CONFIG=config

# Targets
deckard_DIR := tests/integration
deckard := $(libfaketime_DIR)/deckard.py

libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

libswrap_DIR := contrib/libswrap
libswrap_cmake_DIR := $(libswrap_DIR)/obj
libswrap=$(abspath $(libswrap_cmake_DIR))/src/libsocket_wrapper$(LIBEXT).0

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	libswrap=$(abspath $(libswrap_cmake_DIR))/src/libsocket_wrapper.0$(LIBEXT)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime):$(libswrap)"
else
	preload_syms := LD_PRELOAD="$(libfaketime):$(libswrap)"
endif

# Synchronize submodules
$(deckard):
	@git submodule update --init
$(libfaketime_DIR)/Makefile:
	@git submodule update --init
# Build libfaketime contrib
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="" $(MAKE) -C $(libfaketime_DIR)
$(libswrap_DIR):
	@git submodule update --init
$(libswrap_cmake_DIR):$(libswrap_DIR)
	mkdir $(libswrap_cmake_DIR)
$(libswrap_cmake_DIR)/Makefile: $(libswrap_cmake_DIR)
	@cd $(libswrap_cmake_DIR); cmake ..
$(libswrap): $(libswrap_cmake_DIR)/Makefile
	@CFLAGS="-O2 -g" $(MAKE) -C $(libswrap_cmake_DIR)

check-integration: $(deckard) $(libswrap) $(libfaketime)
	$(preload_syms) tests/integration/deckard.py $(TESTS) $(DAEMON) $(TEMPLATE) $(CONFIG) $(ADDITIONAL)

.PHONY: check-integration
