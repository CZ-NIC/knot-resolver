#
# Integration tests
#
# 1. Run tests from main Deckard repo (generic DNS tests)
# 2. Run Deckard tests from kresd repo (kresd-specific tests)

# Platform-specific library injection
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(abspath lib):$(DYLD_LIBRARY_PATH)"
else
	preload_syms := LD_LIBRARY_PATH="$(abspath lib):$(LD_LIBRARY_PATH)"
endif

tests_integr := \
	$(wildcard modules/*/*.test.integr) \
	$(wildcard modules/*/*/*.test.integr)

# Integration tests from Deckard repo
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
deckard: check-install-precond $(deckard_DIR)/Makefile
	$(if $(SUBMODULES_DIRTY), $(warning Warning: Git submodules are not up-to-date),)
	@mkdir -p $(deckard_DIR)/contrib/libswrap/obj
	+TESTS=$(TESTS) DAEMON=$(abspath $(SBINDIR)/kresd) TEMPLATE=$(TEMPLATE) COVERAGE_ENV_SCRIPT=$(TOPSRCDIR)/scripts/coverage_env.sh DAEMONSRCDIR=$(TOPSRCDIR) COVERAGE_STATSDIR=$(COVERAGE_STATSDIR)/deckard $(preload_syms) $(deckard_DIR)/kresd_run.sh

check-integration: deckard

.PHONY: deckard check-integration
