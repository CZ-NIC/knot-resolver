# Project
MAJOR := 15
MINOR := 04

# Paths
PREFIX := /usr/local
BINDIR := /bin
LIBDIR := /lib
INCLUDEDIR := /include
MODULEDIR := $(LIBDIR)/kdns_modules

# Tools
ifndef CC
CC	:= cc
endif
CFLAGS	+= -std=c99 -D_GNU_SOURCE -Wall -fPIC -I$(abspath .)
CFLAGS  += -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR)\"" -DPREFIX="\"$(PREFIX)\"" -DMODULEDIR="\"$(MODULEDIR)\""
RM	:= rm -f
LN  := ln -s
INSTALL := install
PYTHON := python