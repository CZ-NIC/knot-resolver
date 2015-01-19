# Knot DNS Resolver

## Preparation

The Knot DNS Resolver depends on the Knot DNS library which is introduced in current master, and on the
reasonably recent version of the `libuv`.

### libuv

If the libuv with a version at least 1.0 is not present on your system,
compile and install the sources code from the Git repository.

```
$ git clone https://github.com/libuv/libuv.git
$ cd libuv
$ ./autogen.sh
$ make && make install
```

## Compilation

```
$ export PKG_CONFIG_PATH="..." # Change, if you installed the libknot somewhere else
$ ./configure
$ autoreconf -if
$ make
```

## Running

There is a separate resolver library in the `lib` directory, and a minimalistic daemon in
the `daemon` directory. The daemon accepts a few CLI parameters, and there's no support for configuration
right now.

```
$ ./daemon/kresolved -h
$ ./daemon/kresolved -a 127.0.0.1#53
```
