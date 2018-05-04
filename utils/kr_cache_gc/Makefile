
all: kr_cache_gc

kr_cache_gc: kr_cache_gc.o categories.o db.o main.c kr_cache_gc.h ../../lib/defines.h
	gcc -std=gnu99 -o $@ main.c kr_cache_gc.o categories.o db.o -Wl,-Bdynamic -L../../lib -lknot -lkres -I../..

kr_cache_gc.o: kr_cache_gc.c kr_cache_gc.h categories.h db.h ../../contrib/dynarray.h ../../lib/defines.h ../../lib/cache/api.h ../../lib/cache/impl.h
	gcc -std=gnu99 -o $@ -c $< -I../.. -I../../contrib -I/usr/include/luajit-2.0

categories.o: categories.c categories.h kr_cache_gc.h
	gcc -std=gnu99 -o $@ -c $<

db.o: db.c db.h kr_cache_gc.h
	 gcc -std=gnu99 -o $@ -c $< -I../.. -I../../contrib -I/usr/include/luajit-2.0

clean:
	rm -f kr_cache_gc kr_cache_gc.o categories.o db.o

