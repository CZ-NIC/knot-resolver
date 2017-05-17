# Knot DNS Resolver

[![Build Status](https://img.shields.io/travis/CZ-NIC/knot-resolver/master.svg)](https://travis-ci.org/CZ-NIC/knot-resolver)
[![Coverage Status](https://img.shields.io/coveralls/CZ-NIC/knot-resolver.svg)](https://coveralls.io/r/CZ-NIC/knot-resolver)
[![Coverity](https://img.shields.io/coverity/scan/3912.svg)](https://scan.coverity.com/projects/3912)
[![Documentation Status](https://readthedocs.org/projects/knot-resolver/badge/?version=latest)](https://readthedocs.org/projects/knot-resolver/?badge=latest)


Knot DNS Resolver is a caching full resolver implementation written in C and [LuaJIT][luajit], both a resolver library and a daemon. The core architecture is tiny and efficient, and provides a foundation and
a state-machine like API for extensions. There are four of those built-in - *iterator*, *validator* and two caching modules. Most of the [rich features](https://knot-resolver.readthedocs.io/en/latest/modules.html) are written in Lua(JIT) and C. Batteries are included, but optional.

The LuaJIT modules, support DNS privacy and DNSSEC, and persistent cache with low memory footprint make it a great personal DNS resolver or a research tool to tap into DNS data. TL;DR it's the [OpenResty][openresty] of DNS.

Several cache backends (LMDB, Redis and Memcached), strong filtering rules, and auto-configuration with etcd make it a great large-scale resolver solution.

The server adopts a [different scaling strategy][scaling] than the rest of the DNS recursors - no threading, shared-nothing architecture (except MVCC cache that may be shared) that allows you to pin instances on available CPU cores and grow by self-replication. You can start and stop additional nodes depending on the contention without downtime.

It also has strong support for DNS over TCP, notably TCP Fast-Open, query pipelining and deduplication, and response reordering.

### Packages

Knot Resolver is packaged for
[Debian](https://packages.debian.org/sid/knot-resolver),
[Fedora](https://apps.fedoraproject.org/packages/knot-resolver/),
[Ubuntu](https://packages.ubuntu.com/zesty/knot-resolver),
[Homebrew](https://github.com/Homebrew/homebrew-core/blob/master/Formula/knot-resolver.rb) and
[NixOS/Nixpkgs](https://hydra.nixos.org/search?query=knot-resolver).
You can also find it as the default DNS resolver in our open-source router [Turris Omnia](https://omnia.turris.cz).
See the [Knot-resolver homepage](https://www.knot-resolver.cz/pages/try.html) for more information.

<!-- [openSUSE](https://build.opensuse.org/package/show/server:dns/knot-resolver), (it seems to be in a bad shape) -->

### Building from sources

Knot DNS Resolver mainly [depends][depends] on Knot DNS libraries, [LuaJIT][luajit] and [libuv][libuv].
See the [Building project][depends] documentation page for more information.

### Docker image

This is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run -it cznic/knot-resolver
```

See the build page [hub.docker.com/r/cznic/knot-resolver](https://hub.docker.com/r/cznic/knot-resolver/) for more information and options.

### Running

The project builds a resolver library in the `lib` directory, and a daemon in the `daemon` directory. It requires no configuration or parameters to run a server on localhost.

```
$ kresd
```

See the documentation at [knot-resolver.readthedocs.io][doc] for more options.

[depends]: https://knot-resolver.readthedocs.io/en/latest/build.html
[doc]: https://knot-resolver.readthedocs.io/en/latest/index.html
[scaling]: https://knot-resolver.readthedocs.io/en/latest/daemon.html#scaling-out
[deckard]: https://gitlab.labs.nic.cz/knot/deckard
[luajit]: https://luajit.org/
[libuv]: http://libuv.org
[openresty]: https://openresty.org/

### Contacting us

[![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
