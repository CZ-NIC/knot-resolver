# Project
MAJOR := 2
MINOR := 0
PATCH := 0
EXTRA :=
ABIVER := 5
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
ETCDIR ?= $(PREFIX)/etc/knot-resolver
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

ifeq (,$(findstring -O,$(CFLAGS)))
	BUILD_CFLAGS += -O2
endif
ifeq (,$(findstring -fsanitize=address,$(CFLAGS)))
	BUILD_CFLAGS += -D_FORTIFY_SOURCE=2
endif
