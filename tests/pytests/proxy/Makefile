CC=gcc
CFLAGS_TLS=-DDEBUG -ggdb3 -O0 -lgnutls -luv -lasan -fsanitize=address -fno-omit-frame-pointer

all: tlsproxy

tlsproxy: tls-proxy.o tlsproxy.o
	$(CC) tls-proxy.o tlsproxy.o -o tlsproxy $(CFLAGS_TLS)

tls-proxy.o: tls-proxy.c tls-proxy.h array.h
	$(CC) -c -o $@ $< $(CFLAGS_TLS)

tlsproxy.o: tlsproxy.c tls-proxy.h
	$(CC) -c -o $@ $< $(CFLAGS_TLS)

clean:
	rm -f tls-proxy.o tlsproxy.o tlsproxy

.PHONY: all clean
