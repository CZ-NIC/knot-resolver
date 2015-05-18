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
CFLAGS	+= -std=c99 -D_GNU_SOURCE -Wall -fPIC -I$(abspath .) -I$(abspath lib/generic) -I$(abspath contrib)
CFLAGS  += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\""
RM	:= rm -f
LN      := ln -s
XXD     ?= hexdump -v -e '/1 "0x%02X, " " "'
INSTALL := install
PYTHON  := python
