# Project
MAJOR := 1
MINOR := 0
PATCH := 0-beta3
ABIVER := 1
BUILDMODE := dynamic
HARDENING := yes

# Paths
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCLUDEDIR := $(PREFIX)/include
MODULEDIR := $(LIBDIR)/kdns_modules
ETCDIR := $(PREFIX)/etc/kresd

# Tools
CC	?= cc
RM	:= rm -f
LN      := ln -s
XXD     := ./scripts/embed.sh
INSTALL := install

# Flags
BUILD_LDFLAGS += $(LDFLAGS)
BUILD_CFLAGS := $(CFLAGS) -std=c99 -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -Wno-unused -Wtype-limits -Wformat -Wformat-security -Wall -I$(abspath .) -I$(abspath lib/generic) -I$(abspath contrib)
BUILD_CFLAGS += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR).$(PATCH)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\"" -DETCDIR="\"$(ETCDIR)\""
