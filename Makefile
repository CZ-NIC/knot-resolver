include config.mk
include platform.mk

# Targets
all: info libkresolve modules kresolved
install: libkresolve-install modules-install kresolved-install
check: all tests-check
clean: libkresolve-clean modules-clean kresolved-clean tests-clean
.PHONY: all install check clean

# Options
ifdef COVERAGE
CFLAGS += --coverage
endif

# Dependencies
$(eval $(call find_lib,libknot))
$(eval $(call find_lib,libknot-int))
$(eval $(call find_lib,libuv))
$(eval $(call find_lib,cmocka))
$(eval $(call find_python))
CFLAGS += $(libknot_CFLAGS) $(libuv_CFLAGS) $(cmocka_CFLAGS) $(python_CFLAGS)

# Sub-targets
include help.mk
include lib/libkresolve.mk
include daemon/kresolved.mk
include modules/modules.mk
include tests/tests.mk
