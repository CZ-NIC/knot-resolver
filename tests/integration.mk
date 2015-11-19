# Config
TESTS=tests/integration/sets/resolver
TEMPLATE=template/kresd.j2

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

# Build contrib libraries
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="" $(MAKE) -C $(libfaketime_DIR)
$(libswrap_DIR):
	@git submodule update --init
$(libswrap_cmake_DIR): $(libswrap_DIR)
	@mkdir $(libswrap_cmake_DIR)
$(libswrap_cmake_DIR)/Makefile: $(libswrap_cmake_DIR)
	@cd $(libswrap_cmake_DIR); cmake ..
$(libswrap): $(libswrap_cmake_DIR)/Makefile
	@CFLAGS="-O2 -g" $(MAKE) -s -C $(libswrap_cmake_DIR)

deckard: check-integration
check-integration: $(deckard) $(libswrap) $(libfaketime)
	@$(preload_LIBS) $(preload_syms) python tests/integration/deckard.py $(TESTS) $(abspath daemon/kresd) $(TEMPLATE) config

.PHONY: deckard check-integration
