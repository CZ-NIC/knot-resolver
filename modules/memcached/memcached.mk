memcached_CFLAGS := -fPIC
memcached_SOURCES := modules/memcached/memcached.c modules/memcached/cdb_memcached.c
memcached_DEPEND := $(libkres)
memcached_LIBS := $(libkres_TARGET) $(libkres_LIBS) $(libmemcached_LIBS)
$(call make_c_module,memcached)
