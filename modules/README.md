# Knot DNS Resolver extensions

The resolver library[^lib] leverages the [processing API][processing] from the libknot to separate packet processing code
into layers. In order to keep the core library sane and coverable, there are only two built-in layers:
the [iterator](lib/layer/iterate.c), and the [cache](lib/layer/itercache.c). The resolver context however can
load shared libraries on runtime, which allows us to build and register external modules as well.

## Supported languages

Currently modules written in C are supported.
There is also a rudimentary support for writing modules in Go &mdash; ⑴ the library has no native Go bindings, library is accessible using [CGO][cgo], ⑵ gc doesn't support building shared libraries, [GCCGO][gccgo] is required, ⑶ no coroutines and no garbage collecting thread, as the Go code is called from C threads.

There is a plan for Lua scriptables, but it's not implemented yet.

## Available services

## The anatomy of an extension

### Writing a module in C

### Writing a module in Go

[^lib]: See the Knot DNS Resolver library [documentation](lib/README.md).
[processing]: https://gitlab.labs.nic.cz/labs/knot/tree/master/src/libknot/processing
[cgo]: http://golang.org/cmd/cgo/
[gccgo]: https://golang.org/doc/install/gccgo