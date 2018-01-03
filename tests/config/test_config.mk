#
# Configuration tests
#
# Copy test folder and test_utils.lua to temp directory
# Run kresd in temp directory and use config test.cfg
# Check return code of kresd. Passed test have to call quit().

tests_config := \
	$(wildcard modules/*/*_test.lua) \
	$(wildcard tests/config/*_test.lua)

define make_config_test
$(1): check-install-precond
	@$(preload_syms) ./tests/config/runtest.sh $(abspath $(SBINDIR)/kresd) $(abspath $(1))
$(1)-clean:
	@$(RM) $(dir $(1))/luacov.stats.out
.PHONY: $(1)
endef

$(foreach test,$(tests_config),$(eval $(call make_config_test,$(test))))
check-config: $(tests_config)
check-config-clean: $(foreach test,$(tests_config),$(test)-clean)
.PHONY: check-config
