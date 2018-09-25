#
# Unit tests
#

tests_BIN := \
	test_array \
	test_lru \
	test_map \
	test_module \
	test_pack \
	test_queue \
	test_rplan \
	test_set \
	test_trie \
	test_utils \
	test_zonecut \
	#test_cache TODO: re-consider how best to test cache

mock_cmodule_CFLAGS := -fPIC
mock_cmodule_SOURCES := tests/mock_cmodule.c
$(eval $(call make_lib,mock_cmodule,tests))

# Dependencies
tests_DEPEND := $(libkres) $(mock_cmodule) $(mock_gomodule)
tests_LIBS :=  $(libkres_TARGET) $(libkres_LIBS) $(cmocka_LIBS) $(lmdb_LIBS)

# Make test binaries
define make_test
$(1)_CFLAGS := -fPIE
$(1)_SOURCES := tests/$(1).c
$(1)_LIBS := $(tests_LIBS)
$(1)_DEPEND := $(tests_DEPEND)
$(call make_bin,$(1),tests)
$(1): $$($(1))
	$(shell ./scripts/coverage_env.sh "$(TOPSRCDIR)" "$(COVERAGE_STATSDIR)/tests_unit" "$(1)") $(preload_syms) $(DEBUGGER) $$<
.PHONY: $(1)
endef

# Targets
$(foreach test,$(tests_BIN),$(eval $(call make_test,$(test))))
check-unit: $(foreach test,$(tests_BIN),$(test))

.PHONY: check-unit
