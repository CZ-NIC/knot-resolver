# Knot DNS Resolver

[![Build Status](https://img.shields.io/travis/CZ-NIC/knot-resolver/master.svg)](https://travis-ci.org/CZ-NIC/knot-resolver)
[![Coverage Status](https://img.shields.io/coveralls/CZ-NIC/knot-resolver.svg)](https://coveralls.io/r/CZ-NIC/knot-resolver)
[![Coverity](https://img.shields.io/coverity/scan/3912.svg)](https://scan.coverity.com/projects/3912)
[![Documentation Status](https://readthedocs.org/projects/knot-resolver/badge/?version=latest)](https://readthedocs.org/projects/knot-resolver/?badge=latest)


The Knot DNS Resolver is a caching full resolver implementation written in C and [LuaJIT][luajit], including both a resolver
library and a daemon. Modular architecture of the library keeps the core tiny and efficient, and provides
a state-machine like API for extensions. There are three built-in modules - *iterator*, *cache*, *validator*, and many external.

The Lua modules, switchable and shareable cache, and fast FFI bindings makes it great to tap into resolution process, or be used for your recursive DNS service. It's the [OpenResty][openresty] of DNS.

The server adopts a [different scaling strategy][scaling] than the rest of the DNS recursors - no threading, shared-nothing architecture (except MVCC cache that may be shared). You can start and stop additional nodes depending on the contention without downtime.

### Try it out?

Keep in mind that the Knot DNS Resolver is in beta. While it's being tested by the [DNS test harness][deckard], we'll be super glad to hear out your feedback!

### Building from sources

The Knot DNS Resolver [depends][depends] on the 2.0.1 version of the Knot DNS library, [LuaJIT][luajit] and [libuv][libuv].
See the [Building project][depends] documentation page for more information.

### Docker image

This is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run -it cznic/knot-resolver
```

See the build page [hub.docker.com/r/cznic/knot-resolver](https://hub.docker.com/r/cznic/knot-resolver/) for more information and options.

### Running

The project builds a resolver library in the `lib` directory, and a daemon in the `daemon` directory.

```
$ kresd -h
```

See the documentation at [knot-resolver.readthedocs.org][doc].

[depends]: http://knot-resolver.readthedocs.org/en/latest/build.html
[doc]: http://knot-resolver.readthedocs.org/en/latest/index.html
[scaling]: http://knot-resolver.readthedocs.org/en/latest/daemon.html#scaling-out
[deckard]: https://gitlab.labs.nic.cz/knot/deckard
[luajit]: http://luajit.org/
[libuv]: https://github.com/libuv/libuv
[openresty]: https://openresty.org/

### Contacting us

[![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
