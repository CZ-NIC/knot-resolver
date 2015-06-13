# Project
MAJOR := 15
MINOR := 07
PATCH := 0

# Paths
PREFIX := /usr/local
BINDIR := /bin
LIBDIR := /lib
INCLUDEDIR := /include
MODULEDIR := $(LIBDIR)/kdns_modules

# Tools
CC	?= cc
CFLAGS	+= -std=c99 -D_GNU_SOURCE -fPIC -Wall -I$(abspath .) -I$(abspath lib/generic) -I$(abspath contrib)
CFLAGS  += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\""
RM	:= rm -f
LN      := ln -s
XXD     := ./scripts/embed.sh
INSTALL := install
PYTHON  := python
