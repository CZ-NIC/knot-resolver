#
# Configuration tests
#
# Copy test folder and test_utils.lua to temp directory
# Run kresd in temp directory and use config test.cfg
# Check return code of kresd. Passed test have to call quit().

tests_config := \
	basic \
	hints \
	predict

define make_config_test
test-config-$(1): tests/config/$(1)/test.cfg check-install-precond
	@$(preload_syms) ./tests/config/runtest.sh $(abspath $(SBINDIR)/kresd) $(1)
.PHONY: test-$(1)
endef

$(foreach test,$(tests_config),$(eval $(call make_config_test,$(test))))
check-config: $(foreach test,$(tests_config),test-config-$(test))

.PHONY: check-config
