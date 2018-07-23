#
# Integration tests
#
# 1. Run tests from main Deckard repo (generic DNS tests)
# 2. Run tests from kresd repo (kresd-specific tests)

SUBMODULES_DIRTY := $(shell git submodule status --recursive | cut -c 1 | grep -q '[^ ]' && echo $$?)
REAL_PREFIX=$(realpath $(PREFIX))
REAL_CURDIR=$(realpath $(CURDIR))

# Integration tests from Deckard repo
deckard_DIR := $(TOPSRCDIR)/tests/deckard

$(deckard_DIR)/Makefile:
	@git submodule update --init --recursive

# this is necessary to avoid multiple parallel but independent runs
# of 'make depend' from $(deckard_DIR)/run.sh
$(deckard_DIR)/env.sh: $(deckard_DIR)/Makefile
	@make -C "$(deckard_DIR)" depend

check-install-precond:
	$(if $(SUBMODULES_DIRTY), $(warning Warning: Git submodules are not up-to-date, expect test failures),)
	$(if $(findstring $(REAL_CURDIR),$(REAL_PREFIX)),, $(warning Warning: PREFIX does not point into source directory; testing version in $(PREFIX)!))
	@test -x "$(SBINDIR)/kresd" || (echo 'to run integration tests install kresd into into $$PREFIX ($(SBINDIR)/kresd)' && exit 1)

# Deckard requires additional depedencies so it is not part of installcheck
deckard: check-install-precond $(deckard_DIR)/env.sh
	COVERAGE_ENV_SCRIPT="$(TOPSRCDIR)/scripts/coverage_env.sh" DAEMONSRCDIR="$(TOPSRCDIR)" COVERAGE_STATSDIR="$(COVERAGE_STATSDIR)/deckard" $(preload_syms) PATH="$(SBINDIR):$(PATH)" "$(deckard_DIR)/kresd_run.sh"


tests_integr := \
	$(wildcard daemon/*.test.integr) \
	$(wildcard modules/*/*.test.integr) \
	$(wildcard modules/*/test.integr) \
	$(wildcard modules/*/*/test.integr) \
	$(wildcard modules/*/*/*.test.integr)

define make_integr_test
$(1): check-install-precond $(deckard_DIR)/env.sh
	echo "Integration tests from $1" && cd "$(TOPSRCDIR)" && COVERAGE_ENV_SCRIPT="$(TOPSRCDIR)/scripts/coverage_env.sh" DAEMONSRCDIR="$(TOPSRCDIR)" COVERAGE_STATSDIR="$(COVERAGE_STATSDIR)/deckard" $(preload_syms) PATH="$(SBINDIR):$(PATH)" "$(deckard_DIR)/run.sh" "--config=$(abspath $(1))/deckard.yaml" "--scenarios=$(abspath $(1))"
.PHONY: $(1)
endef

$(foreach test,$(tests_integr),$(eval $(call make_integr_test,$(test))))

check-integration: deckard $(tests_integr)
.PHONY: check-install-precond deckard check-integration $(tests_integr)
