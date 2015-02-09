# Project
MAJOR := 15
MINOR := 04

# Paths
PREFIX := /usr/local
BINDIR := /bin
LIBDIR := /lib
INCLUDEDIR = /include

# Tools
ifndef CC
CC	:= cc
endif
CFLAGS	+= -std=c99 -D_GNU_SOURCE -Wall -fPIC -I$(abspath .) -DPACKAGE_VERSION="\"$(MAJOR).$(MINOR)\""
RM	:= rm -f
LN  := ln -s
INSTALL := install
PYTHON := python