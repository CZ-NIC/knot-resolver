contrib_SOURCES := \
	contrib/ccan/asprintf/asprintf.c \
	contrib/ccan/ilog/ilog.c \
	contrib/ccan/isaac/isaac.c \
	contrib/ccan/json/json.c \
	contrib/ucw/mempool.c \
	contrib/murmurhash3/murmurhash3.c \
	contrib/base32hex.c
contrib_CFLAGS := -fPIC
contrib_TARGET := $(abspath contrib)/contrib$(AREXT)
$(eval $(call make_static,contrib,contrib))
