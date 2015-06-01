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
	test_rplan \
	test_resolve

mock_cmodule_SOURCES := tests/mock_cmodule.c
$(eval $(call make_lib,mock_cmodule,tests))
mock_gomodule_SOURCES := tests/mock_gomodule.c
$(eval $(call make_lib,mock_gomodule,tests))

# Dependencies
tests_DEPEND := $(libkresolve) $(mock_cmodule) $(mock_gomodule)
tests_LIBS :=  $(libkresolve_TARGET) $(libkresolve_LIBS) $(cmocka_LIBS)

# Make test binaries
define make_test
$(1)_SOURCES := tests/$(1).c
$(1)_LIBS := $(tests_LIBS)
$(1)_DEPEND := $(tests_DEPEND)
$(call make_bin,$(1),tests)
$(1)-run: $$($(1))
	$(call preload_LIBS) $$<
.PHONY: $(1)-run
endef

# Targets
$(foreach test,$(tests_BIN),$(eval $(call make_test,$(test))))
check-unit: $(foreach test,$(tests_BIN),$(test)-run)

.PHONY: check-unit
