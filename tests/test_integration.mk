#
# Integration tests
#
# 1. Run tests from main Deckard repo (generic DNS tests)

SUBMODULES_DIRTY := $(shell git submodule status --recursive | cut -c 1 | grep -q '[^ ]' && echo $$?)
REAL_PREFIX=$(realpath $(PREFIX))
REAL_CURDIR=$(realpath $(CURDIR))

# Platform-specific library injection
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(abspath $(LIBDIR)):$(DYLD_LIBRARY_PATH)"
else
	preload_syms := LD_LIBRARY_PATH="$(abspath $(LIBDIR)):$(LD_LIBRARY_PATH)"
endif

# Integration tests from Deckard repo
deckard_DIR := tests/deckard

$(deckard_DIR)/Makefile:
	@git submodule update --init --recursive

check-install-precond:
	$(if $(SUBMODULES_DIRTY), $(warning Warning: Git submodules are not up-to-date, expect test failures),)
	$(if $(findstring $(REAL_CURDIR),$(REAL_PREFIX)),, $(warning Warning: PREFIX does not point into source directory; testing version in $(PREFIX)!))
	@test -x "$(SBINDIR)/kresd" || (echo 'to run integration tests install kresd into into $$PREFIX ($(SBINDIR)/kresd)' && exit 1)

# Deckard requires additional depedencies so it is not part of installcheck
deckard: check-install-precond $(deckard_DIR)/Makefile
	COVERAGE_ENV_SCRIPT="$(TOPSRCDIR)/scripts/coverage_env.sh" DAEMONSRCDIR="$(TOPSRCDIR)" COVERAGE_STATSDIR="$(COVERAGE_STATSDIR)/deckard" $(preload_syms) PATH="$(SBINDIR):$$PATH" "$(deckard_DIR)/kresd_run.sh"

check-integration: deckard

.PHONY: check-install-precond deckard check-integration
