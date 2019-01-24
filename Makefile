SHELL=/bin/bash -o pipefail -o errexit

include config.mk
include platform.mk

# Targets
all: info lib daemon client modules etc
install: lib-install daemon-install client-install modules-install etc-install
check: all tests
clean: contrib-clean lib-clean daemon-clean client-clean modules-clean \
	tests-clean doc-clean bench-clean coverage-clean
doc: doc-html
lint: lint-lua lint-c
lint-c: libkres-lint kresd-lint kresc-lint
lint-lua: $(patsubst %.lua.in,%.lua,$(wildcard */*/*.lua.in))
	luacheck --codes --formatter TAP .

.PHONY: all install check clean doc info lint

# Dependencies
KNOT_MINVER := 2.7.6
$(eval $(call find_lib,libknot,$(KNOT_MINVER),yes))
$(eval $(call find_lib,libdnssec,$(KNOT_MINVER),yes))
$(eval $(call find_lib,libzscanner,$(KNOT_MINVER),yes))
$(eval $(call find_lib,lmdb))
$(eval $(call find_lib,libuv,1.0,yes))
$(eval $(call find_lib,nettle,,yes))
$(eval $(call find_alt,lua,luajit))
$(eval $(call find_luapkg,ltn12))
$(eval $(call find_luapkg,ssl.https))
$(eval $(call find_lib,cmocka))
$(eval $(call find_bin,doxygen))
$(eval $(call find_bin,sphinx-build))
$(eval $(call find_pythonpkg,breathe))
$(eval $(call find_lib,socket_wrapper))
$(eval $(call find_lib,libsystemd,227))
$(eval $(call find_lib,gnutls))
$(eval $(call find_lib,libedit))
$(eval $(call find_lib,libprotobuf-c,1))
$(eval $(call find_lib,libfstrm,0.2))
$(eval $(call find_bin,protoc-c))
$(eval $(call find_bin,lcov))
$(eval $(call find_bin,luacov))

# Lookup SONAME
$(eval $(call find_soname,libknot))
$(eval $(call find_soname,libzscanner))

ifeq ($(libknot_SONAME),)
  $(error "Unable to resolve libknot_SONAME, update find_soname in platform.mk")
endif
ifeq ($(libzscanner_SONAME),)
  $(error "Unable to resolve libzscanner_SONAME, update find_some in platform.mk")
endif

# Find Go version and platform
GO_VERSION := $(shell $(GO) version 2>/dev/null)
ifeq ($(GO_VERSION),)
        GO_VERSION := 0
else
        GO_PLATFORM := $(word 2,$(subst /, ,$(word 4,$(GO_VERSION))))
        GO_VERSION := $(subst .,,$(subst go,,$(word 3,$(GO_VERSION))))
endif
$(eval $(call find_ver,go,$(GO_VERSION),16))

# Check if Go is able to build shared libraries
ifeq ($(HAS_go),yes)
ifneq ($(GO_PLATFORM),$(filter $(GO_PLATFORM),amd64 386 arm arm64))
HAS_go := no
endif
else
$(eval $(call find_ver,go,$(GO_VERSION),15))
ifeq ($HAS_go,yes)
ifneq ($(GO_PLATFORM),$(filter $(GO_PLATFORM),arm amd64))
HAS_go := no
endif
endif
endif

# check for fstrm and protobuf for dnstap
ifeq ($(HAS_libfstrm)|$(HAS_libprotobuf-c)|$(HAS_protoc-c),yes|yes|yes)
ENABLE_DNSTAP := yes
endif

# Overview
info:
	$(info Target:     Knot Resolver $(VERSION)-$(PLATFORM))
	$(info Compiler:   $(CC) $(BUILD_CFLAGS))
	$(info Linker:     $(CCLD) $(BUILD_LDFLAGS))
	$(info )
	$(info Variables)
	$(info ---------)
	$(info HARDENING:  $(HARDENING))
	$(info BUILDMODE:  $(BUILDMODE))
	$(info PREFIX:     $(PREFIX))
	$(info PREFIX:     $(PREFIX))
	$(info DESTDIR:    $(DESTDIR))
	$(info BINDIR:     $(BINDIR))
	$(info SBINDIR:    $(SBINDIR))
	$(info LIBDIR:     $(LIBDIR))
	$(info ETCDIR:     $(ETCDIR))
	$(info INCLUDEDIR: $(INCLUDEDIR))
	$(info MODULEDIR:  $(MODULEDIR))
	$(info )
	$(info Core Dependencies)
	$(info ------------)
	$(info [$(HAS_libknot)] libknot (lib))
	$(info [yes] $(if $(filter $(HAS_lmdb),yes),system,embedded) lmdb (lib))
	$(info [$(HAS_lua)] luajit (daemon))
	$(info [$(HAS_libuv)] libuv (daemon))
	$(info [$(HAS_gnutls)] libgnutls (daemon))
	$(info )
	$(info Optional)
	$(info --------)
	$(info [$(HAS_doxygen)] doxygen (doc))
	$(info [$(HAS_sphinx-build)] sphinx-build (doc))
	$(info [$(HAS_breathe)] python-breathe (doc))
	$(info [$(HAS_go)] go (modules/go, Go buildmode=c-shared support))
	$(info [$(HAS_cmocka)] cmocka (tests/unit))
	$(info [$(HAS_libsystemd)] systemd (daemon))
#	$(info [$(HAS_nettle)] nettle (modules/cookies))
	$(info [$(HAS_ltn12)] Lua socket ltn12 (trust anchor bootstrapping))
	$(info [$(HAS_ssl.https)] Lua ssl.https (trust anchor bootstrapping))
	$(info [$(HAS_libedit)] libedit (client))
	$(info [$(HAS_libfstrm)] libfstrm (modules/dnstap))
	$(info [$(HAS_libprotobuf-c)] libprotobuf-c (modules/dnstap))
	$(info [$(HAS_protoc-c)] proto-c (modules/dnstap))
	$(info [$(HAS_lcov)] lcov (code coverage))
	$(info [$(HAS_luacov)] luacov (code coverage))
	$(info )

# Verify required dependencies are met, as listed above
ifeq ($(HAS_libknot),no)
	$(error libknot >= $(KNOT_MINVER) required)
endif
ifeq ($(HAS_libzscanner),no)
	$(error libzscanner >= $(KNOT_MINVER) required)
endif
ifeq ($(HAS_libdnssec),no)
	$(error libdnssec >= $(KNOT_MINVER) required)
endif
ifeq ($(HAS_lua),no)
	$(error luajit required)
endif
ifeq ($(HAS_libuv),no)
	$(error libuv >= 1.0 required)
endif
ifeq ($(HAS_gnutls),no)
	$(error gnutls required)
endif


BUILD_CFLAGS += $(libknot_CFLAGS) $(libuv_CFLAGS) $(nettle_CFLAGS) $(cmocka_CFLAGS) $(lua_CFLAGS) $(libdnssec_CFLAGS) $(libsystemd_CFLAGS)
BUILD_CFLAGS += $(addprefix -I,$(wildcard contrib/ccan/*) contrib/murmurhash3)

# Work around luajit on OS X
ifeq ($(PLATFORM), Darwin)
ifneq (,$(findstring luajit, $(lua_LIBS)))
	lua_LIBS += -pagezero_size 10000 -image_base 100000000
endif
endif

# Check if it has nettle to support DNS cookies

# temporarily turn off cookies
#ifeq ($(HAS_nettle), yes)
#BUILD_CFLAGS += -DENABLE_COOKIES
#ENABLE_COOKIES := yes
#endif
ENABLE_COOKIES := no

# Installation directories
$(DESTDIR)$(MODULEDIR):
	$(INSTALL) -d $@
$(DESTDIR)$(ETCDIR):
	$(INSTALL) -m 0755 -d $@

# Sub-targets
include contrib/contrib.mk
include coverage.mk
include lib/lib.mk
include client/client.mk
include daemon/daemon.mk
include modules/modules.mk
include tests/tests.mk
include doc/doc.mk
include etc/etc.mk
include bench/bench.mk
