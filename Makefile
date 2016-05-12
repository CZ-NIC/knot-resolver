include config.mk
include platform.mk

# Targets
all: info lib daemon modules
install: lib-install daemon-install modules-install etc-install
check: all tests
clean: contrib-clean lib-clean daemon-clean modules-clean tests-clean doc-clean
doc: doc-html
.PHONY: all install check clean doc info

# Options
ifdef COVERAGE
BUILD_CFLAGS += --coverage
endif

# Dependencies
$(eval $(call find_lib,libknot,2.1))
$(eval $(call find_lib,libzscanner,2.1))
$(eval $(call find_lib,libuv,1.0))
$(eval $(call find_alt,lua,luajit))
$(eval $(call find_lib,cmocka))
$(eval $(call find_bin,doxygen))
$(eval $(call find_bin,sphinx-build))
$(eval $(call find_lib,libmemcached,1.0))
$(eval $(call find_lib,hiredis))
$(eval $(call find_lib,socket_wrapper))
$(eval $(call find_lib,libdnssec))
$(eval $(call find_lib,libsystemd))
$(eval $(call find_gopkg,geoip,github.com/abh/geoip))

GO_VERSION  := $(shell $(GO) version | sed -e 's/^go version go\([0-9]\)[.]\([0-9]\)[.]\([0-9]\) .*/\1\2/')
GO_PLATFORM := $(shell $(GO) version | sed -e 's,^go version go[0-9.]* linux/,,')

$(eval $(call find_ver,go,$(GO_VERSION),16))

ifeq ($(HAS_go),yes)
ifneq ($(GO_PLATFORM),$(filter $(GO_PLATFORM),amd64 386 arm arm64))
HAS_go := no
endif
else
$(eval $(call find_ver,go,$(GO_VERSION),15))
ifeq ($HAS_go,yes)
ifneq($(GO_PLATFORM),$(filter $(GO_PLATFORM),arm amd64))
HAS_go := no
endif
endif

# Work around luajit on OS X
ifeq ($(PLATFORM), Darwin)
ifneq (,$(findstring luajit, $(lua_LIBS)))
	lua_LIBS += -pagezero_size 10000 -image_base 100000000
endif
endif

BUILD_CFLAGS += $(libknot_CFLAGS) $(libuv_CFLAGS) $(cmocka_CFLAGS) $(lua_CFLAGS) $(libdnssec_CFLAGS) $(libsystemd_CFLAGS)
BUILD_CFLAGS += $(addprefix -I,$(wildcard contrib/ccan/*) contrib/murmurhash3)

# Overview
info:
	$(info Target:     Knot DNS Resolver $(MAJOR).$(MINOR).$(PATCH)-$(PLATFORM))
	$(info Compiler:   $(CC) $(BUILD_CFLAGS))
	$(info )
	$(info Variables)
	$(info ---------)
	$(info HARDENING:  $(HARDENING))
	$(info BUILDMODE:  $(BUILDMODE))
	$(info PREFIX:     $(PREFIX))
	$(info PREFIX:     $(PREFIX))
	$(info DESTDIR:    $(DESTDIR))
	$(info BINDIR:     $(BINDIR))
	$(info LIBDIR:     $(LIBDIR))
	$(info ETCDIR:     $(ETCDIR))
	$(info INCLUDEDIR: $(INCLUDEDIR))
	$(info MODULEDIR:  $(MODULEDIR))
	$(info )
	$(info Dependencies)
	$(info ------------)
	$(info [$(HAS_libknot)] libknot (lib))
	$(info [$(HAS_lua)] luajit (daemon))
	$(info [$(HAS_libuv)] libuv (daemon))
	$(info )
	$(info Optional)
	$(info --------)
	$(info [$(HAS_doxygen)] doxygen (doc))
	$(info [$(HAS_go)] go (modules/go, Go buildmode=c-shared support))
	$(info [$(HAS_geoip)] geoip (modules/tinyweb, github.com/abh/geoip))
	$(info [$(HAS_libmemcached)] libmemcached (modules/memcached))
	$(info [$(HAS_hiredis)] hiredis (modules/redis))
	$(info [$(HAS_cmocka)] cmocka (tests/unit))
	$(info [$(HAS_libsystemd)] systemd (daemon))
	$(info )

# Installation directories
$(DESTDIR)$(MODULEDIR):
	$(INSTALL) -d $@
$(DESTDIR)$(ETCDIR):
	$(INSTALL) -m 0750 -d $@

# Sub-targets
include contrib/contrib.mk
include lib/lib.mk
include daemon/daemon.mk
include modules/modules.mk
include tests/tests.mk
include doc/doc.mk
include etc/etc.mk
