# Project
MAJOR := 15
MINOR := 04
PATCH := 0

# Paths
PREFIX := /usr/local
BINDIR := /bin
LIBDIR := /lib
INCLUDEDIR := /include
MODULEDIR := $(LIBDIR)/kdns_modules

# Tools
CC	?= cc
CFLAGS	+= -std=c99 -D_GNU_SOURCE -Wall -fPIC -I$(abspath .) -I$(abspath lib/generic)
CFLAGS  += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\""
RM	:= rm -f
LN      := ln -s
XXD     ?= xxd
INSTALL := install
PYTHON  := python
