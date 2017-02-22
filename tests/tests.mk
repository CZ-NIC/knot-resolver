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

REAL_PREFIX=$(realpath $(PREFIX))
REAL_CURDIR=$(realpath $(CURDIR))

$(deckard_DIR)/Makefile:
	@git submodule update --init --recursive

check-integration: $(deckard_DIR)/Makefile
	$(if $(findstring $(REAL_CURDIR),$(REAL_PREFIX)),, $(warning Warning: PREFIX does not point into source directory; testing the installed version!))
	@mkdir -p $(deckard_DIR)/contrib/libswrap/obj
	+TESTS=$(TESTS) DAEMON=$(abspath $(SBINDIR)/kresd) TEMPLATE=$(TEMPLATE) $(preload_syms) $(deckard_DIR)/kresd_run.sh

deckard: check-integration

# Targets
tests: check-unit
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) mock_cmodule-clean clean-dnstap

.PHONY: tests tests-clean check-integration deckard
