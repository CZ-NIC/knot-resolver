redis_CFLAGS := -fvisibility=hidden -fPIC
redis_SOURCES := modules/redis/redis.c modules/redis/namedb_redis.c
redis_LIBS := $(libkres_TARGET) $(libkres_LIBS) $(hiredis_LIBS) $(libuv_LIBS)
$(call make_c_module,redis)
