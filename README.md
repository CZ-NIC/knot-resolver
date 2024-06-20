# Knot Resolver

[![Build Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/pipeline.svg?x)](https://gitlab.nic.cz/knot/knot-resolver/commits/nightly)
[![Coverage Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/coverage.svg?x)](https://www.knot-resolver.cz/documentation/latest)
[![Packaging status](https://repology.org/badge/tiny-repos/knot-resolver.svg)](https://repology.org/project/knot-resolver/versions)

Knot Resolver is a full caching DNS resolver implementation. The core architecture is tiny and efficient, written in C and [LuaJIT][luajit], providing a foundation and a state-machine-like API for extension modules. There are three built-in modules - *iterator*, *validator* and *cache* - which provide the main functionality of the resolver. A few other modules are automatically loaded by default to extend the resolver's functionality.

Since Knot Resolver version 6, it also includes a so-called [manager][manager]. It is a new component written in [Python][python] that hides the complexity of older versions and makes it more user friendly. For example, new features include declarative configuration in YAML format and HTTP API for dynamic changes in the resolver and more.

Knot Resolver uses a [different scaling strategy][scaling] than the rest of the DNS resolvers - no threading, shared-nothing architecture (except MVCC cache which can be shared), which allows you to pin workers to available CPU cores and grow by self-replication. You can start and stop additional workers based on the contention without downtime, which is automated by the [manager][manager] by default.

The LuaJIT modules, support for DNS privacy and DNSSEC, and persistent cache with low memory footprint make it a great personal DNS resolver or a research tool to tap into DNS data. Strong filtering rules, and auto-configuration with etcd make it a great large-scale resolver solution. It also has strong support for DNS over TCP, in particular TCP Fast-Open, query pipelining and deduplication, and response reordering.

For more on using the resolver, see the [User Documentation][doc]. See the [Developer Documentation][doc-dev] for detailed architecture and development.

## Packages

The latest stable packages for various distributions are available in our
[upstream repository](https://pkg.labs.nic.cz/doc/?project=knot-resolver).
Follow the installation instructions to add this repository to your system.

Knot Resolver is also available from the following distributions' repositories:

* [Fedora and Fedora EPEL](https://src.fedoraproject.org/rpms/knot-resolver)
* [Debian stable](https://packages.debian.org/stable/knot-resolver),
  [Debian testing](https://packages.debian.org/testing/knot-resolver),
  [Debian unstable](https://packages.debian.org/sid/knot-resolver)
* [Ubuntu](https://packages.ubuntu.com/jammy/knot-resolver)
* [Arch Linux](https://archlinux.org/packages/extra/x86_64/knot-resolver/)
* [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=knot-resolver)

### Packaging

The project uses [`apkg`](https://gitlab.nic.cz/packaging/apkg) for packaging.
See [`distro/README.md`](distro/README.md) for packaging specific instructions.

## Building from sources

Knot Resolver mainly depends on [KnotDNS][knot-dns] libraries, [LuaJIT][luajit], [libuv][libuv] and [Python][python].

See the [Building project][build] documentation page for more information.

## Running

By default, Knot Resolver comes with [systemd][systemd] integration and you just need to start its service. It requires no configuration changes to run a server on localhost.

```
# systemctl start knot-resolver
```

See the documentation at [knot-resolver.cz/documentation/latest][doc] for more information.

## Running the Docker image

Running the Docker image is simple and doesn't require any dependencies or system modifications, just run:

```
$ docker run -Pit cznic/knot-resolver
```

The images are meant as an easy way to try the resolver, and they're not designed for production use.

## Contacting us

- [GitLab issues](https://gitlab.nic.cz/knot/knot-resolver/issues) (you may authenticate via GitHub)
- [mailing list](https://lists.nic.cz/postorius/lists/knot-resolver-announce.lists.nic.cz/)
- [![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[build]: https://www.knot-resolver.cz/documentation/latest/dev/build.html
[doc]: https://www.knot-resolver.cz/documentation/latest/
[doc-dev]: https://www.knot-resolver.cz/documentation/latest/dev
[knot-dns]: https://www.knot-dns.cz/
[luajit]: https://luajit.org/
[libuv]: http://libuv.org
[python]: https://www.python.org/
[systemd]: https://systemd.io/
[scaling]: https://www.knot-resolver.cz/documentation/latest/config-multiple-workers.html
[manager]: https://www.knot-resolver.cz/documentation/latest/dev/architecture.html
