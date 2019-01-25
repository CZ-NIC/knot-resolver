Building project
================

Installing from packages
------------------------

The resolver is packaged for Debian, Fedora+EPEL, Ubuntu, Docker, NixOS/NixPkgs, FreeBSD, HomeBrew, and Turris Omnia.
Some of these are maintained directly by the knot-resolver team.

Refer to `project page <https://www.knot-resolver.cz/download>`_ for information about
installing from packages. If packages are not available for your OS, see following sections
to see how you can build it from sources (or package it), or use official `Docker images`_.

Platform considerations
-----------------------

Knot-resolver is written for UNIX-like systems, mainly in C99.
Portable I/O is provided by libuv_.
Some 64-bit systems with LuaJIT 2.1 may be affected by
`a problem <https://github.com/LuaJIT/LuaJIT/blob/v2.1/doc/status.html#L100>`_
-- Linux on x86_64 is unaffected but `Linux on aarch64 is
<https://gitlab.labs.nic.cz/knot/knot-resolver/issues/216>`_.

Windows systems might theoretically work without large changes,
but it's most likely broken and currently not planned to be supported.

Requirements
------------

The following is a list of software required to build Knot Resolver from sources.

.. csv-table::
   :header: "Requirement", "Required by", "Notes"

   "`GNU Make`_ 3.80+", "*all*", "*(build only)*"
   "C and C++ compiler", "*all*", "*(build only)* [#]_"
   "`pkg-config`_", "*all*", "*(build only)* [#]_"
   "hexdump or xxd", "``daemon``", "*(build only)*"
   "libknot_ 2.7.6+", "*all*", "Knot DNS libraries"
   "LuaJIT_ 2.0+", "``daemon``", "Embedded scripting language."
   "libuv_ 1.7+", "*all*", "Multiplatform I/O and services."
   "lmdb", "*all*", ""
   "GnuTLS", "*all*", ""

There are also *optional* packages that enable specific functionality in Knot Resolver, they are useful mainly for developers to build documentation and tests.

.. csv-table::
   :header: "Optional", "Needed for", "Notes"

   "`lua-http`_", "``modules/http``", "HTTP/2 client/server for Lua."
   "luasocket_", "``trust anchors, modules/stats``", "Sockets for Lua."
   "luasec_", "``trust anchors``", "TLS for Lua."
   "cmocka_", "``unit tests``", "Unit testing framework."
   "Doxygen_", "``documentation``", "Generating API documentation."
   "Sphinx_ and sphinx_rtd_theme_", "``documentation``", "Building this HTML/PDF documentation."
   "breathe_", "``documentation``", "Exposing Doxygen API doc to Sphinx."
   "libsystemd_", "``daemon``", "Systemd socket activation support."
   "libprotobuf_ 3.0+", "``modules/dnstap``", "Protocol Buffers support for dnstap_."
   "`libprotobuf-c`_ 1.0+", "``modules/dnstap``", "C bindings for Protobuf."
   "libfstrm_ 0.2+", "``modules/dnstap``", "Frame Streams data transport protocol."
   "luacheck_", "``lint-lua``", "Syntax and static analysis checker for Lua."
   "`clang-tidy`_", "``lint-c``", "Syntax and static analysis checker for C."
   "luacov_", "``check-config``", "Code coverage analysis for Lua modules."

.. [#] Requires C99, ``__attribute__((cleanup))`` and ``-MMD -MP`` for dependency file generation. GCC, Clang and ICC are supported.
.. [#] You can use variables ``<dependency>_CFLAGS`` and ``<dependency>_LIBS`` to configure dependencies manually (i.e. ``libknot_CFLAGS`` and ``libknot_LIBS``).
.. [#] libuv 1.7 brings SO_REUSEPORT support that is needed for multiple forks. libuv < 1.7 can be still used, but only in single-process mode. Use :ref:`different method <daemon-reuseport>` for load balancing.

Packaged dependencies
~~~~~~~~~~~~~~~~~~~~~

Most of the dependencies can be resolved from packages, here's an overview for several platforms.

* **Debian** (since *sid*) - current stable doesn't have libknot and libuv, which must be installed from sources.

.. code-block:: bash

   sudo apt-get install pkg-config libknot-dev libuv1-dev libcmocka-dev libluajit-5.1-dev

* **Ubuntu** - unknown.
* **Fedora**

.. code-block:: bash

   # minimal build
   sudo dnf install @buildsys-build knot-devel libuv-devel luajit-devel
   # unit tests
   sudo dnf install libcmocka-devel
   # integration tests
   sudo dnf install cmake git python-dns python-jinja2
   # optional features
   sudo dnf install lua-sec-compat lua-socket-compat systemd-devel
   # docs
   sudo dnf install doxygen python-breathe python-sphinx

* **RHEL/CentOS** - unknown.
* **openSUSE** - there is an `experimental package <https://build.opensuse.org/package/show/server:dns/knot-resolver>`_.
* **FreeBSD** - when installing from ports, all dependencies will install automatically, corresponding to the selected options.
* **NetBSD** - unknown.
* **OpenBSD** - unknown.
* **Mac OS X** - the dependencies can be found through `Homebrew <http://brew.sh/>`_.

.. code-block:: bash

   brew install pkg-config libuv luajit cmocka

Building from sources
---------------------

Initialize git submodules first.

.. code-block:: bash

    $ git submodule update --init --recursive

The Knot Resolver depends on the the Knot DNS library, recent version of libuv_, and LuaJIT_.

.. code-block:: bash

   $ make info # See what's missing

When you have all the dependencies ready, you can build and install.

.. code-block:: bash

   $ make PREFIX="/usr/local"
   $ make install PREFIX="/usr/local"

.. note:: Always build with ``PREFIX`` if you want to install, as it is hardcoded in the executable for module search path.
    Production code should be compiled with ``-DNDEBUG``.
    If you build the binary with ``-DNOVERBOSELOG``, it won't be possible to turn on verbose logging; we advise packagers against using that flag.

.. note:: If you build with ``PREFIX``, you may need to also set the ``LDFLAGS`` for the libraries:

.. code-block:: bash

   make LDFLAGS="-Wl,-rpath=/usr/local/lib" PREFIX="/usr/local"

Alternatively you can build only specific parts of the project, i.e. ``library``.

.. code-block:: bash

   $ make lib
   $ make lib-install

.. note:: Documentation is not built by default, run ``make doc`` to build it.

Building with security compiler flags
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Knot Resolver enables certain `security compile-time flags <https://wiki.debian.org/Hardening#Notes_on_Memory_Corruption_Mitigation_Methods>`_ that do not affect performance.
You can add more flags to the build by appending them to `CFLAGS` variable, e.g. ``make CFLAGS="-fstack-protector"``.

  .. csv-table::
   :header: "Method", "Status", "Notes"

   "-fstack-protector", "*disabled*", "(must be specifically enabled in CFLAGS)"
   "-D_FORTIFY_SOURCE=2", "**enabled**", ""
   "-pie", "**enabled**", "enables ASLR for kresd (disable with ``make HARDENING=no``)"
   "RELRO", "**enabled**", "full [#]_"

You can also disable linker hardening when it's unsupported with ``make HARDENING=no``.

.. [#] See `checksec.sh <http://www.trapkit.de/tools/checksec.html>`_

Building for packages
~~~~~~~~~~~~~~~~~~~~~

The build system supports DESTDIR_

TODO no longer support, use meson --prefix instead (DESTDIR will cause invalid path to modules)

.. Our amalgamation has fallen into an unmaintained state and probably doesn't work.
.. and `amalgamated builds <https://www.sqlite.org/amalgamation.html>`_.

.. code-block:: bash

   $ make install DESTDIR=/tmp/stage
..   $ make all install AMALG=yes # Amalgamated build

.. Amalgamated build assembles everything in one source file and compiles it. It is useful for packages, as the compiler sees the whole program and is able to produce a smaller and faster binary. On the other hand, it complicates debugging.

.. tip:: There is a template for service file and AppArmor profile to help you kickstart the package.

Default paths
~~~~~~~~~~~~~

The default installation follows FHS with several custom paths for configuration and modules.
All paths are prefixed with ``PREFIX`` variable by default if not specified otherwise.

  .. csv-table::
   :header: "Component", "Variable", "Default", "Notes"

   "library", "``LIBDIR``", "``$(PREFIX)/lib``", "pkg-config is auto-generated [#]_"
   "daemon",  "``SBINDIR``", "``$(PREFIX)/sbin``", ""
   "configuration", "``ETCDIR``", "``$(PREFIX)/etc/knot-resolver``", "Configuration file, templates."
   "modules", "``MODULEDIR``", "``$(LIBDIR)/kdns_modules``", "Runtime directory for loading dynamic modules [#]_."
   "trust anchor file", "``keyfile_default``", "*(none)*", "Path to read-only trust anchor file, which is used as fallback when no other file is specified. [#]_"
   "work directory", "", "the current directory", "Run directory for daemon. (Only relevant during run time, not e.g. during installation.)"

.. [#] The ``libkres.pc`` is installed in ``$(LIBDIR)/pkgconfig``.
.. [#] The default moduledir can be changed with `-m` option to `kresd` daemon or by calling `moduledir()` function from lua.
.. [#] If no other trust anchor is specified by user, the compiled-in path ``keyfile_default`` must contain a valid trust anchor. This is typically used by distributions which provide DNSSEC root trust anchors as part of distribution package. Users can disable the built-in trust anchor by adding ``trust_anchors.keyfile_default = nil`` to their configuration.

.. note:: Each module is self-contained and may install additional bundled files within ``$(MODULEDIR)/$(modulename)``. These files should be read-only, non-executable.

Static or dynamic?
~~~~~~~~~~~~~~~~~~

By default the resolver library is built as a dynamic library with versioned ABI. You can revert to static build with ``BUILDMODE`` variable.

.. code-block:: bash

   $ make BUILDMODE=dynamic # Default, create dynamic library
   $ make BUILDMODE=static  # Create static library

When the library is linked statically, it usually produces a smaller binary. However linking it to various C modules might violate ODR and increase the size.

Resolving dependencies
~~~~~~~~~~~~~~~~~~~~~~

The build system relies on `pkg-config`_ to find dependencies.
You can override it to force custom versions of the software by environment variables.

.. code-block:: bash

   $ make libknot_CFLAGS="-I/opt/include" libknot_LIBS="-L/opt/lib -lknot -ldnssec"

Optional dependencies may be disabled as well using ``HAS_x=yes|no`` variable.

.. code-block:: bash

   $ make HAS_go=no HAS_cmocka=no

.. warning:: If the dependencies lie outside of library search path, you need to add them somehow.
   Try ``LD_LIBRARY_PATH`` on Linux/BSD, and ``DYLD_FALLBACK_LIBRARY_PATH`` on OS X.
   Otherwise you need to add the locations to linker search path.

Building extras
~~~~~~~~~~~~~~~

The project can be built with code coverage tracking using the ``COVERAGE=1`` variable.

The `make coverage` target gathers both gcov code coverage for C files, and luacov_ code coverage for Lua files and merges it for analysis. It requires lcov_ to be installed.

.. code-block:: bash

   $ make coverage

Running unit and integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The linter requires luacheck_ and `clang-tidy`_ and is executed by ``make lint``.
The unit tests require cmocka_ and are executed by ``make check``.
Tests for the dnstap module need go and are executed by ``make ckeck-dnstap``.

The integration tests use Deckard, the `DNS test harness <deckard>`_.

.. code-block:: bash

	$  make check-integration

Note that the daemon and modules must be installed first before running integration tests, the reason is that the daemon
is otherwise unable to find and load modules.

Read the `documentation <deckard_doc>`_ for more information about requirements, how to run it and extend it.

Getting Docker image
--------------------

Docker images require only either Linux or a Linux VM (see boot2docker_ on OS X).

.. code-block:: bash

   $ docker run cznic/knot-resolver

See the `Docker images`_ page for more information and options.
You can hack on the container by changing the container entrypoint to shell like:

.. code-block:: bash

   $ docker run -it --entrypoint=/bin/bash cznic/knot-resolver

.. tip:: You can build the Docker image yourself with ``docker build -t knot-resolver scripts``.

.. _Docker images: https://hub.docker.com/r/cznic/knot-resolver
.. _libuv: https://github.com/libuv/libuv
.. _MSVC: https://msdn.microsoft.com/en-us/vstudio/hh386302.aspx
.. _MinGW: http://www.mingw.org/
.. _Dockerfile: https://registry.hub.docker.com/u/cznic/knot-resolver/dockerfile/

.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _Go: https://golang.org
.. _geoip: https://github.com/abh/geoip
.. _Doxygen: https://www.stack.nl/~dimitri/doxygen/manual/index.html
.. _breathe: https://github.com/michaeljones/breathe
.. _Sphinx: http://sphinx-doc.org/
.. _sphinx_rtd_theme: https://pypi.python.org/pypi/sphinx_rtd_theme
.. _GNU Make: https://www.gnu.org/software/make/
.. _pkg-config: https://www.freedesktop.org/wiki/Software/pkg-config/
.. _libknot: https://gitlab.labs.nic.cz/knot/knot-dns
.. _cmocka: https://cmocka.org/
.. _Python: https://www.python.org/
.. _luasec: https://luarocks.org/modules/brunoos/luasec
.. _luasocket: https://luarocks.org/modules/luarocks/luasocket
.. _lua-http: https://luarocks.org/modules/daurnimator/http

.. _boot2docker: http://boot2docker.io/

.. _deckard: https://gitlab.labs.nic.cz/knot/deckard
.. _deckard_doc: https://gitlab.labs.nic.cz/knot/knot-resolver/blob/master/tests/README.rst

.. _libsystemd: https://www.freedesktop.org/wiki/Software/systemd/
.. _dnstap: http://dnstap.info/
.. _libprotobuf: https://developers.google.com/protocol-buffers/
.. _libprotobuf-c: https://github.com/protobuf-c/protobuf-c/wiki
.. _libfstrm: https://github.com/farsightsec/fstrm
.. _luacheck: http://luacheck.readthedocs.io
.. _clang-tidy: http://clang.llvm.org/extra/clang-tidy/index.html
.. _luacov: https://keplerproject.github.io/luacov/
.. _lcov: http://ltp.sourceforge.net/coverage/lcov.php

.. _DESTDIR: https://www.gnu.org/prep/standards/html_node/DESTDIR.html
