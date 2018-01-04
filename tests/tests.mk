# Platform-specific library injection
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(abspath lib):$(DYLD_LIBRARY_PATH)"
else
	preload_syms := LD_LIBRARY_PATH="$(abspath lib):$(LD_LIBRARY_PATH)"
endif

# Unit tests
ifeq ($(HAS_cmocka), yes)
include tests/unit.mk
else
$(warning cmocka not found, skipping unit tests)
endif

include tests/config/test_config.mk

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

check-install-precond:
	$(if $(findstring $(REAL_CURDIR),$(REAL_PREFIX)),, $(warning Warning: PREFIX does not point into source directory; testing version in $(PREFIX)!))

# Deckard requires additional depedencies so it is not part of installcheck
check-integration: check-install-precond $(deckard_DIR)/Makefile
	$(if $(SUBMODULES_DIRTY), $(warning Warning: Git submodules are not up-to-date),)
	@mkdir -p $(deckard_DIR)/contrib/libswrap/obj
	+TESTS=$(TESTS) DAEMON=$(abspath $(SBINDIR)/kresd) TEMPLATE=$(TEMPLATE) COVERAGE_ENV_SCRIPT=$(TOPSRCDIR)/scripts/coverage_env.sh DAEMONSRCDIR=$(TOPSRCDIR) COVERAGE_STATSDIR=$(COVERAGE_STATSDIR)/deckard $(preload_syms) $(deckard_DIR)/kresd_run.sh

deckard: check-integration

# Targets
tests: check-unit
# installcheck requires kresd to be installed in its final destination
# (DESTDIR is not supported right now because module path gets hardcoded)
installcheck: check-config
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) mock_cmodule-clean $(CLEAN_DNSTAP)

.PHONY: check-integration deckard installcheck tests tests-clean
