# Unit tests
ifeq ($(HAS_cmocka), yes)
include tests/unit.mk
else
$(warning cmocka not found, skipping unit tests)
endif

ifeq ($(ENABLE_DNSTAP)|$(HAS_go),yes|yes)
include tests/dnstap/src/dnstap-test/dnstap.mk
endif

# Integration tests with Deckard
deckard_DIR := tests/deckard
TESTS := sets/resolver
TEMPLATE := template/kresd.j2
$(deckard_DIR)/Makefile:
	@git submodule update --init --recursive
check-integration: $(deckard_DIR)/Makefile
	@mkdir -p $(deckard_DIR)/contrib/libswrap/obj
	@$(MAKE) -s -C $(deckard_DIR) TESTS=$(TESTS) DAEMON=$(abspath daemon/kresd) TEMPLATE=$(TEMPLATE) DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH)
deckard: check-integration

# Targets
tests: check-unit
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) mock_cmodule-clean

.PHONY: tests tests-clean check-integration deckard
