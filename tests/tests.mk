# Unit tests
ifeq ($(HAS_cmocka), yes)
include tests/unit.mk
else
$(warning cmocka not found, skipping unit tests)
endif

CLEAN_DNSTAP :=
ifeq ($(ENABLE_DNSTAP)|$(HAS_go),yes|yes)
include tests/dnstap/src/dnstap-test/dnstap.mk
CLEAN_DNSTAP := clean-dnstap
endif

# Integration tests with Deckard
deckard_DIR := tests/deckard
TESTS := sets/resolver
TEMPLATE := template/kresd.j2
SUBMODULES_DIRTY := $(shell git submodule status --recursive | cut -c 1 | grep -q '[^ ]' && echo $$?)

REAL_PREFIX=$(realpath $(PREFIX))
REAL_CURDIR=$(realpath $(CURDIR))

$(deckard_DIR)/Makefile:
	@git submodule update --init --recursive

check-integration: $(deckard_DIR)/Makefile
	$(if $(findstring $(REAL_CURDIR),$(REAL_PREFIX)),, $(warning Warning: PREFIX does not point into source directory; testing the installed version!))
	$(if $(SUBMODULES_DIRTY), $(warning Warning: Git submodules are not up-to-date),)
	@mkdir -p $(deckard_DIR)/contrib/libswrap/obj
	+TESTS=$(TESTS) DAEMON=$(abspath $(SBINDIR)/kresd) TEMPLATE=$(TEMPLATE) $(preload_syms) $(deckard_DIR)/kresd_run.sh

deckard: check-integration

# Targets
tests: check-unit
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) mock_cmodule-clean $(CLEAN_DNSTAP)

.PHONY: tests tests-clean check-integration deckard
