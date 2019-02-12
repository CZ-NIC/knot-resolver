contrib_SOURCES := \
	contrib/ccan/asprintf/asprintf.c \
	contrib/ccan/ilog/ilog.c \
	contrib/ucw/mempool.c \
	contrib/ucw/mempool-fmt.c \
	contrib/murmurhash3/murmurhash3.c \
	contrib/base32hex.c \
	contrib/base64.c
contrib_CFLAGS := -fPIC
contrib_TARGET := $(abspath contrib)/contrib$(AREXT)

ifneq ($(LIBRARY_ONLY), yes)
contrib_SOURCES += contrib/ccan/json/json.c

# Use built-in LMDB if not found
ifneq ($(HAS_lmdb), yes)
contrib_SOURCES += contrib/lmdb/mdb.c \
                   contrib/lmdb/midl.c
contrib_CFLAGS  += -pthread
contrib_LIBS    += -pthread
lmdb_CFLAGS     += -I$(abspath contrib/lmdb)
endif
endif


$(eval $(call make_static,contrib,contrib))
