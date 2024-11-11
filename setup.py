# -*- coding: utf-8 -*-
from setuptools import setup

package_dir = \
{'': 'python'}

packages = \
['knot_resolver',
 'knot_resolver.client',
 'knot_resolver.client.commands',
 'knot_resolver.controller',
 'knot_resolver.controller.supervisord',
 'knot_resolver.controller.supervisord.plugin',
 'knot_resolver.datamodel',
 'knot_resolver.datamodel.templates',
 'knot_resolver.datamodel.types',
 'knot_resolver.manager',
 'knot_resolver.manager.metrics',
 'knot_resolver.utils',
 'knot_resolver.utils.compat',
 'knot_resolver.utils.modeling']

package_data = \
{'': ['*'], 'knot_resolver.datamodel.templates': ['macros/*']}

install_requires = \
['aiohttp', 'jinja2', 'pyyaml', 'supervisor', 'typing-extensions']

extras_require = \
{'prometheus': ['prometheus-client']}

entry_points = \
{'console_scripts': ['knot-resolver = knot_resolver.manager.main:main',
                     'kresctl = knot_resolver.client.main:main']}

setup_kwargs = {
    'name': 'knot-resolver',
    'version': '6.0.9',
    'description': 'Knot Resolver Manager - a Python program that automatically manages the other components of the resolver',
    'long_description': "# Knot Resolver\n\n[![Build Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/pipeline.svg?x)](https://gitlab.nic.cz/knot/knot-resolver/commits/nightly)\n[![Coverage Status](https://gitlab.nic.cz/knot/knot-resolver/badges/nightly/coverage.svg?x)](https://www.knot-resolver.cz/documentation/latest)\n[![Packaging status](https://repology.org/badge/tiny-repos/knot-resolver.svg)](https://repology.org/project/knot-resolver/versions)\n\nKnot Resolver is a full caching DNS resolver implementation. The core architecture is tiny and efficient, written in C and [LuaJIT][luajit], providing a foundation and a state-machine-like API for extension modules. There are three built-in modules - *iterator*, *validator* and *cache* - which provide the main functionality of the resolver. A few other modules are automatically loaded by default to extend the resolver's functionality.\n\nSince Knot Resolver version 6, it also includes a so-called [manager][manager]. It is a new component written in [Python][python] that hides the complexity of older versions and makes it more user friendly. For example, new features include declarative configuration in YAML format and HTTP API for dynamic changes in the resolver and more.\n\nKnot Resolver uses a [different scaling strategy][scaling] than the rest of the DNS resolvers - no threading, shared-nothing architecture (except MVCC cache which can be shared), which allows you to pin workers to available CPU cores and grow by self-replication. You can start and stop additional workers based on the contention without downtime, which is automated by the [manager][manager] by default.\n\nThe LuaJIT modules, support for DNS privacy and DNSSEC, and persistent cache with low memory footprint make it a great personal DNS resolver or a research tool to tap into DNS data. Strong filtering rules, and auto-configuration with etcd make it a great large-scale resolver solution. It also has strong support for DNS over TCP, in particular TCP Fast-Open, query pipelining and deduplication, and response reordering.\n\nFor more on using the resolver, see the [User Documentation][doc]. See the [Developer Documentation][doc-dev] for detailed architecture and development.\n\n## Packages\n\nThe latest stable packages for various distributions are available in our\n[upstream repository](https://pkg.labs.nic.cz/doc/?project=knot-resolver).\nFollow the installation instructions to add this repository to your system.\n\nKnot Resolver is also available from the following distributions' repositories:\n\n* [Fedora and Fedora EPEL](https://src.fedoraproject.org/rpms/knot-resolver)\n* [Debian stable](https://packages.debian.org/stable/knot-resolver),\n  [Debian testing](https://packages.debian.org/testing/knot-resolver),\n  [Debian unstable](https://packages.debian.org/sid/knot-resolver)\n* [Ubuntu](https://packages.ubuntu.com/jammy/knot-resolver)\n* [Arch Linux](https://archlinux.org/packages/extra/x86_64/knot-resolver/)\n* [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=knot-resolver)\n\n### Packaging\n\nThe project uses [`apkg`](https://gitlab.nic.cz/packaging/apkg) for packaging.\nSee [`distro/README.md`](distro/README.md) for packaging specific instructions.\n\n## Building from sources\n\nKnot Resolver mainly depends on [KnotDNS][knot-dns] libraries, [LuaJIT][luajit], [libuv][libuv] and [Python][python].\n\nSee the [Building project][build] documentation page for more information.\n\n## Running\n\nBy default, Knot Resolver comes with [systemd][systemd] integration and you just need to start its service. It requires no configuration changes to run a server on localhost.\n\n```\n# systemctl start knot-resolver\n```\n\nSee the documentation at [knot-resolver.cz/documentation/latest][doc] for more information.\n\n## Running the Docker image\n\nRunning the Docker image is simple and doesn't require any dependencies or system modifications, just run:\n\n```\n$ docker run -Pit cznic/knot-resolver\n```\n\nThe images are meant as an easy way to try the resolver, and they're not designed for production use.\n\n## Contacting us\n\n- [GitLab issues](https://gitlab.nic.cz/knot/knot-resolver/issues) (you may authenticate via GitHub)\n- [mailing list](https://lists.nic.cz/postorius/lists/knot-resolver-announce.lists.nic.cz/)\n- [![Join the chat at https://gitter.im/CZ-NIC/knot-resolver](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/CZ-NIC/knot-resolver?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)\n\n[build]: https://www.knot-resolver.cz/documentation/latest/dev/build.html\n[doc]: https://www.knot-resolver.cz/documentation/latest/\n[doc-dev]: https://www.knot-resolver.cz/documentation/latest/dev\n[knot-dns]: https://www.knot-dns.cz/\n[luajit]: https://luajit.org/\n[libuv]: http://libuv.org\n[python]: https://www.python.org/\n[systemd]: https://systemd.io/\n[scaling]: https://www.knot-resolver.cz/documentation/latest/config-multiple-workers.html\n[manager]: https://www.knot-resolver.cz/documentation/latest/dev/architecture.html\n",
    'author': 'Aleš Mrázek',
    'author_email': 'ales.mrazek@nic.cz',
    'maintainer': 'Aleš Mrázek',
    'maintainer_email': 'ales.mrazek@nic.cz',
    'url': 'https://www.knot-resolver.cz',
    'package_dir': package_dir,
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'extras_require': extras_require,
    'entry_points': entry_points,
    'python_requires': '>=3.8,<4.0',
}
from build_c_extensions import *
build(setup_kwargs)

setup(**setup_kwargs)


# This setup.py was autogenerated using Poetry for backward compatibility with setuptools.
