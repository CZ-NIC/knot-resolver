# Project
MAJOR := 1
MINOR := 0
PATCH := 0-beta2

# Paths
PREFIX := /usr/local
BINDIR := /bin
LIBDIR := /lib
INCLUDEDIR := /include
MODULEDIR := $(LIBDIR)/kdns_modules
ETCDIR := /etc/kresd

# Tools
CC	?= cc
BUILD_LDFLAGS += $(LDFLAGS)
BUILD_CFLAGS := $(CFLAGS) -std=c99 -D_GNU_SOURCE -fPIC -Wtype-limits -Wall -I$(abspath .) -I$(abspath lib/generic) -I$(abspath contrib)
BUILD_CFLAGS += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR).$(PATCH)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\"" -DETCDIR="\"$(ETCDIR)\""
RM	:= rm -f
LN      := ln -s
XXD     := ./scripts/embed.sh
INSTALL := install
