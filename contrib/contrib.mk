contrib_SOURCES := \
	contrib/ccan/asprintf/asprintf.c \
	contrib/ccan/ilog/ilog.c \
	contrib/ccan/isaac/isaac.c \
	contrib/ccan/json/json.c \
	contrib/ucw/mempool.c \
	contrib/murmurhash3/murmurhash3.c \
	contrib/base32hex.c \
	contrib/base64.c
contrib_CFLAGS := -fPIC
contrib_TARGET := $(abspath contrib)/contrib$(AREXT)

# Use built-in LMDB if not found
ifneq ($(HAS_lmdb), yes)
contrib_SOURCES += contrib/lmdb/mdb.c \
                   contrib/lmdb/midl.c
contrib_CFLAGS  += -pthread
contrib_LIBS    += -pthread
endif

ifeq ($(ENABLE_DNSTAP), yes)
contrib_SOURCES += contrib/dnstap/dnstap.pb-c.c
endif

$(eval $(call make_static,contrib,contrib))
