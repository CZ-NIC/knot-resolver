CC=gcc
CFLAGS_TLS=-DDEBUG -ggdb3 -O0 -lgnutls -luv
CFLAGS_TCP=-DDEBUG -ggdb3 -O0 -luv

all: tcproxy tlsproxy

tlsproxy: tls-proxy.o tlsproxy.o
	$(CC) tls-proxy.o tlsproxy.o -o tlsproxy $(CFLAGS_TLS)

tls-proxy.o: tls-proxy.c tls-proxy.h array.h
	$(CC) -c -o $@ $< $(CFLAGS_TLS)

tlsproxy.o: tlsproxy.c tls-proxy.h
	$(CC) -c -o $@ $< $(CFLAGS_TLS)

tcproxy: tcp-proxy.o tcproxy.o
	$(CC) tcp-proxy.o tcproxy.o -o tcproxy $(CFLAGS_TCP)

tcp-proxy.o: tcp-proxy.c tcp-proxy.h array.h
	$(CC) -c -o $@ $< $(CFLAGS_TCP)

tcproxy.o: tcproxy.c tcp-proxy.h
	$(CC) -c -o $@ $< $(CFLAGS_TCP)

clean:
	rm -f tcp-proxy.o tcproxy.o tcproxy tls-proxy.o tlsproxy.o tlsproxy

.PHONY: all clean
