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
tests-clean: $(foreach test,$(tests_BIN),$(test)-clean) mock_cmodule-clean $(CLEAN_DNSTAP)

# Targets
tests: check-unit
# installcheck requires kresd to be installed in its final destination
# (DESTDIR is not supported right now because module path gets hardcoded)

installcheck: check-config

include tests/config/test_config.mk
include tests/test_integration.mk


.PHONY: installcheck tests tests-clean
