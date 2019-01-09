#
# Configuration tests
#
# Copy test folder and test_utils.lua to temp directory
# Run kresd in temp directory and use config test.cfg
# Check return code of kresd. Passed test have to call quit().

tests_config := \
	$(wildcard daemon/*/*.test.lua) \
	$(wildcard daemon/*/*/*.test.lua) \
	$(wildcard modules/*/*.test.lua) \
	$(wildcard modules/*/*/*.test.lua) \
	$(wildcard tests/config/*.test.lua) \
	$(wildcard tests/config/*/*.test.lua)

define make_config_test
$(1): check-install-precond
	@$(shell ./scripts/coverage_env.sh "$(TOPSRCDIR)" "$(COVERAGE_STATSDIR)/tests_config" "$(1)") $(preload_syms) ./tests/config/runtest.sh $(abspath $(SBINDIR)/kresd) $(abspath $(1))
.PHONY: $(1)
endef

$(foreach test,$(tests_config),$(eval $(call make_config_test,$(test))))
check-config: $(tests_config)
.PHONY: check-config
