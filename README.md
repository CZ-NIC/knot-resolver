# Knot DNS Resolver

[![Build Status](https://gitlab.labs.nic.cz/knot/knot-resolver/badges/master/pipeline.svg?x)](https://gitlab.labs.nic.cz/knot/knot-resolver/commits/master)
[![Coverage Status](https://gitlab.labs.nic.cz/knot/knot-resolver/badges/master/coverage.svg?x)](https://knot.pages.labs.nic.cz/knot-resolver/)
[![Coverity](https://img.shields.io/coverity/scan/3912.svg)](https://scan.coverity.com/projects/3912)
[![Documentation Status](https://readthedocs.org/projects/knot-resolver/badge/?version=latest)](https://readthedocs.org/projects/knot-resolver/?badge=latest)

Knot DNS Resolver is a caching full resolver implementation written in C and [LuaJIT][luajit], both a resolver library and a daemon. The core architecture is tiny and efficient, and provides a foundation and
a state-machine like API for extensions. There are three modules built-in - *iterator*, *validator*, *cache*, and a few more are loaded by default. Most of the [rich features](https://knot-resolver.readthedocs.io/en/latest/modules.html) are written in Lua(JIT) and C. Batteries are included, but optional.

The LuaJIT modules, support DNS privacy and DNSSEC, and persistent cache with low memory footprint make it a great personal DNS resolver or a research tool to tap into DNS data. TL;DR it's the [OpenResty][openresty] of DNS.

Strong filtering rules, and auto-configuration with etcd make it a great large-scale resolver solution.

The server adopts a [different scaling strategy][scaling] than the rest of the DNS recursors - no threading, shared-nothing architecture (except MVCC cache that may be shared) that allows you to pin instances on available CPU cores and grow by self-replication. You can start and stop additional nodes depending on the contention without downtime.

It also has strong support for DNS over TCP, notably TCP Fast-Open, query pipelining and deduplication, and response reordering.

### Packages

The latest stable packages for various distributions are available in our
[upstream repository](https://build.opensuse.org/package/show/home:CZ-NIC:knot-resolver-latest/knot-resolver).
Follow the
[installation instructions](https://software.opensuse.org//download.html?project=home%3ACZ-NIC%3Aknot-resolver-latest&package=knot-resolver)
to add this repository to your system.

Knot Resolver is also available from the following distributions' repositories.

* [Fedora and Fedora EPEL](https://apps.fedoraproject.org/packages/knot-resolver)
* [Debian stable](https://packages.debian.org/stable/knot-resolver),
  [Debian testing](https://packages.debian.org/testing/knot-resolver),
  [Debian unstable](https://packages.debian.org/sid/knot-resolver)
* [Ubuntu](https://packages.ubuntu.com/bionic/knot-resolver)
* [Arch Linux (AUR)](https://aur.archlinux.org/packages/knot-resolver)

### Building from sources

Knot DNS Resolver mainly [depends][depends] on Knot DNS libraries, [LuaJIT][luajit] and [libuv][libuv].
See the [Building project][depends] documentation page for more information.

### Docker image

This is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run -it cznic/knot-resolver
```

See the build page [hub.docker.com/r/cznic/knot-resolver](https://hub.docker.com/r/cznic/knot-resolver/) for more information and options.
The images are meant as an easy way to try knot-resolver, and they're not designed for production use.

### Running

The project builds a resolver library in the `lib` directory, and a daemon in the `daemon` directory. It requires no configuration or parameters to run a server on localhost.

```
$ kresd
```

See the documentation at [knot-resolver.readthedocs.io][doc] for more options.

[depends]: https://knot-resolver.readthedocs.io/en/stable/build.html
[doc]: https://knot-resolver.readthedocs.io/en/stable/index.html
[scaling]: https://knot-resolver.readthedocs.io/en/stable/daemon.html#scaling-out
[deckard]: https://gitlab.labs.nic.cz/knot/deckard
[luajit]: https://luajit.org/
[libuv]: http://libuv.org
[openresty]: https://openresty.org/

### Contacting us

- [GitLab issues](https://gitlab.labs.nic.cz/knot/knot-resolver/issues) (you may authenticate via GitHub)
- [mailing list](https://lists.nic.cz/cgi-bin/mailman/listinfo/knot-resolver-users)
- [![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

