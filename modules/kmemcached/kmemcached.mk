kmemcached_SOURCES := modules/kmemcached/kmemcached.c modules/kmemcached/namedb_memcached.c
kmemcached_LIBS := $(libkresolve_TARGET) $(libkresolve_LIBS) $(libmemcached_LIBS)
$(call make_c_module,kmemcached)
