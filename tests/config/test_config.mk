#
# Configuration tests
#
# Copy test folder and test_utils.lua to temp directory
# Run kresd in temp directory and use config test.cfg
# Check return code of kresd. Passed test have to call quit().

tests_lua := \
	hints

check-config:
	$(foreach test,$(tests_lua), \
		@echo "config-test: $(test)" ;\
		export TMP_RUNDIR=`mktemp -d` ;\
		cp "tests/config/$(test)"/* $${TMP_RUNDIR} ;\
		cp tests/config/test_utils.lua $${TMP_RUNDIR} ;\
		$(preload_syms) $(DEBUGGER) $(abspath $(SBINDIR)/kresd) -c test.cfg $${TMP_RUNDIR} > /dev/null ;\
		export retval=$$? ;\
		rm -rf $${TMP_RUNDIR} ;\
		test $${retval} -eq 0 ;\
	)

.PHONY: check-config
