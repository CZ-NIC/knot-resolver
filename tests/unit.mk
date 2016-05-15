#
# Unit tests
#

tests_BIN := \
	test_set \
	test_map \
	test_array \
	test_pack \
	test_lru \
	test_utils \
	test_module \
	test_cache \
	test_zonecut \
	test_rplan

mock_cmodule_CFLAGS := -fPIC
mock_cmodule_SOURCES := tests/mock_cmodule.c
$(eval $(call make_lib,mock_cmodule,tests))

# Dependencies
tests_DEPEND := $(libkres) $(mock_cmodule) $(mock_gomodule)
tests_LIBS :=  $(libkres_TARGET) $(libkres_LIBS) $(cmocka_LIBS) $(lmdb_LIBS)

# Platform-specific library injection
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(DYLD_LIBRARY_PATH):$(abspath lib)"
else
	preload_syms := LD_LIBRARY_PATH="$(LD_LIBRARY_PATH):$(abspath lib)"
endif

# Make test binaries
define make_test
$(1)_CFLAGS := -fPIE
$(1)_SOURCES := tests/$(1).c
$(1)_LIBS := $(tests_LIBS)
$(1)_DEPEND := $(tests_DEPEND)
$(call make_bin,$(1),tests)
$(1): $$($(1))
	@$(preload_syms) $$<
.PHONY: $(1)
endef

# Targets
$(foreach test,$(tests_BIN),$(eval $(call make_test,$(test))))
check-unit: $(foreach test,$(tests_BIN),$(test))

.PHONY: check-unit
