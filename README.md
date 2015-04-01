# Knot DNS Resolver

[![Build Status](https://travis-ci.org/CZ-NIC/knot-resolver.svg?branch=master)](https://travis-ci.org/CZNIC-Labs/knot-resolver)
[![Coverage Status](https://coveralls.io/repos/CZ-NIC/knot-resolver/badge.svg?branch=master)](https://coveralls.io/r/CZNIC-Labs/knot-resolver?branch=master)

The Knot DNS Resolver is a minimalistic caching resolver implementation. The project provides both a resolver
library and a small daemon. Modular architecture of the library keeps the core tiny and efficient, and provides
a state-machine like API for extensions. There are two built-in modules: *iterator* and *cache*,
and each module can be flipped on and off.

### Try it out?

The Knot DNS Resolver is currently in an early development phase, you shouldn't put it in the production right away.

### Docker image

This is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run cznic/knot-resolver
```

See the build page [registry.hub.docker.com/u/cznic/knot-resolver](https://registry.hub.docker.com/u/cznic/knot-resolver) for more information and options.

### Building from sources 

The Knot DNS Resolver [depends][depends] on the development version of the Knot DNS library.
Several dependencies may not be in the packages yet, the script pulls and installs all dependencies in a chroot.

You can avoid rebuilding dependencies by specifying `BUILD_IGNORE` variable, see the [Dockerfile](scripts/Dockerfile)
for example. Usually you only really need to rebuild `libknot`.

```
$ export FAKEROOT="${HOME}/.local"
$ export PKG_CONFIG_PATH="${FAKEROOT}/lib/pkgconfig"
$ ./scripts/bootstrap-depends.sh ${FAKEROOT}
$ make
$ make check
```

### Running

There is a separate resolver library in the `lib` directory, and a daemon in the `daemon` directory.

```
$ ./daemon/kresolved -h
$ ./daemon/kresolved -a "127.0.0.1#53"
```

### More

See the documentation at [knot-resolver.readthedocs.org][doc].

[depends]: http://knot-resolver.readthedocs.org/en/latest/build.html
[doc]: http://knot-resolver.readthedocs.org/en/latest/index.html
