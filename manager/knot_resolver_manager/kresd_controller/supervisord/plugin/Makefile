# !!! Do not use this in production !!!!!
# This makefile is a hack to simplify initial development
#
# Use variant of this instead:
# https://docs.python.org/3/extending/building.html#building

notify.so: notify.o
	gcc -shared notify.o -L/usr/local/lib -o notify.so

notify.o: notifymodule.c
	gcc -DNDEBUG -g -O3 -Wall -Wstrict-prototypes -fPIC -I/usr/local/include -I/usr/include/python3.10 -c notifymodule.c -o notify.o