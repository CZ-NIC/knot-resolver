
all: kr_cache_gc

kr_cache_gc: kr_cache_gc.c ../../contrib/dynarray.h ../../lib/defines.h ../../lib/cache/api.h ../../lib/cache/impl.h
	gcc -std=gnu99 -o $@ $< -Wl,-Bdynamic -L../../lib -lknot -lkres -I../.. -I../../contrib -I/usr/include/luajit-2.0


