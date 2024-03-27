# Knot Resolver

[![Build Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/pipeline.svg?x)](https://gitlab.nic.cz/knot/knot-resolver/commits/nightly)
[![Coverage Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/coverage.svg?x)](https://www.knot-resolver.cz/documentation/latest)
[![Packaging status](https://repology.org/badge/tiny-repos/knot-resolver.svg)](https://repology.org/project/knot-resolver/versions)

Knot Resolver is a caching full resolver implementation written in C and [LuaJIT][luajit], both a resolver library and a daemon. The core architecture is tiny and efficient, and provides a foundation and
a state-machine like API for extensions. There are three modules built-in - *iterator*, *validator*, *cache*, and a few more are loaded by default. Most of the [rich features](https://www.knot-resolver.cz/documentation/latest/config-overview.html) are written in Lua(JIT) and C. Batteries are included, but optional.

The LuaJIT modules, support DNS privacy and DNSSEC, and persistent cache with low memory footprint make it a great personal DNS resolver or a research tool to tap into DNS data. TL;DR it's the [OpenResty][openresty] of DNS.

Strong filtering rules, and auto-configuration with etcd make it a great large-scale resolver solution.

The server adopts a [different scaling strategy][scaling] than the rest of the DNS recursors - no threading, shared-nothing architecture (except MVCC cache that may be shared) that allows you to pin instances on available CPU cores and grow by self-replication. You can start and stop additional nodes depending on the contention without downtime, which is by default automated by the included [manager][manager].

It also has strong support for DNS over TCP, notably TCP Fast-Open, query pipelining and deduplication, and response reordering.

### Packages

The latest stable packages for various distributions are available in our
[upstream repository](https://pkg.labs.nic.cz/doc/?project=knot-resolver).
Follow the installation instructions to add this repository to your system.

Knot Resolver is also available from the following distributions' repositories.

* [Fedora and Fedora EPEL](https://src.fedoraproject.org/rpms/knot-resolver)
* [Debian stable](https://packages.debian.org/stable/knot-resolver),
  [Debian testing](https://packages.debian.org/testing/knot-resolver),
  [Debian unstable](https://packages.debian.org/sid/knot-resolver)
* [Ubuntu](https://packages.ubuntu.com/jammy/knot-resolver)
* [Arch Linux](https://archlinux.org/packages/extra/x86_64/knot-resolver/)
* [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=knot-resolver)

### Building from sources

Knot Resolver mainly [depends][depends] on Knot DNS libraries, [LuaJIT][luajit], and [libuv][libuv].
See the [Building project][depends] documentation page for more information.

### Docker image

This is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run -Pit cznic/knot-resolver
```

The images are meant as an easy way to try knot-resolver, and they're not designed for production use.

### Running

The project builds a resolver library in the `lib` directory, and a daemon in the `daemon` directory. It requires no configuration or parameters to run a server on localhost.

```
$ kresd
```

See the documentation at [knot-resolver.cz/documentation/latest][doc] for more options.

[depends]: https://www.knot-resolver.cz/documentation/latest/dev/build.html
[doc]: https://www.knot-resolver.cz/documentation/latest/
[scaling]: https://www.knot-resolver.cz/documentation/latest/config-multiple-workers.html
[manager]: https://www.knot-resolver.cz/documentation/latest/architecture-manager.html
[deckard]: https://gitlab.nic.cz/knot/deckard
[luajit]: https://luajit.org/
[libuv]: http://libuv.org
[openresty]: https://openresty.org/

### Contacting us

- [GitLab issues](https://gitlab.nic.cz/knot/knot-resolver/issues) (you may authenticate via GitHub)
- [mailing list](https://lists.nic.cz/postorius/lists/knot-resolver-announce.lists.nic.cz/)
- [![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

