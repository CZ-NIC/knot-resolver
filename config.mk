# Project
MAJOR := 1
MINOR := 5
PATCH := 2
EXTRA :=
ABIVER := 4
BUILDMODE := dynamic
HARDENING := yes

VERSION := $(MAJOR).$(MINOR).$(PATCH)$(EXTRA)

# Paths
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig
MANDIR ?= $(PREFIX)/share/man
INCLUDEDIR ?= $(PREFIX)/include
MODULEDIR ?= $(LIBDIR)/kdns_modules
ETCDIR ?= $(PREFIX)/etc/kresd
ROOTHINTS ?= $(ETCDIR)/root.hints
COVERAGE_STAGE ?= gcov
COVERAGE_STATSDIR ?= $(CURDIR)/coverage.stats
TOPSRCDIR := $(CURDIR)
KEYFILE_DEFAULT ?=

# Tools
CC      ?= cc
RM      := rm -f
LN      := ln -s
XXD_LUA := ./scripts/embed-lua.sh
INSTALL := install

# Flags
BUILD_LDFLAGS += $(LDFLAGS)
BUILD_CFLAGS := $(CFLAGS) -std=c99 -D_GNU_SOURCE
BUILD_CFLAGS += -Wno-unused -Wtype-limits -Wformat -Wformat-security -Wall
BUILD_CFLAGS += -I$(abspath .) -I$(abspath lib/generic) -I$(abspath contrib)
BUILD_CFLAGS += -DPACKAGE_VERSION="\"$(VERSION)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\""
BUILD_CFLAGS += -fvisibility=hidden

# Otherwise Fedora is making kresd symbols inaccessible for modules
# TODO: clang needs different flag name, etc.
BUILD_CFLAGS += -rdynamic
BUILD_LDFLAGS += -export-dynamic

ifeq (,$(findstring -O,$(CFLAGS)))
	BUILD_CFLAGS += -O2
endif
ifeq (,$(findstring -fsanitize=address,$(CFLAGS)))
	BUILD_CFLAGS += -D_FORTIFY_SOURCE=2
endif
