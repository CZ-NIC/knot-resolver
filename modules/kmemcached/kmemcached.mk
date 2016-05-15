kmemcached_CFLAGS := -fvisibility=hidden -fPIC
kmemcached_SOURCES := modules/kmemcached/kmemcached.c modules/kmemcached/cdb_memcached.c
kmemcached_DEPEND := $(libkres)
kmemcached_LIBS := $(libkres_TARGET) $(libkres_LIBS) $(libmemcached_LIBS)
$(call make_c_module,kmemcached)
