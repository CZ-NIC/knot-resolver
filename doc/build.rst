Building from sources
=====================

.. note:: Latest up-to-date packages for various distribution can be obtained
   from `<https://knot-resolver.cz/download/>`_

Knot-resolver is written for UNIX-like systems, mainly in C99.
Portable I/O is provided by libuv_.
Some 64-bit systems with LuaJIT 2.1 may be affected by
`a problem <https://github.com/LuaJIT/LuaJIT/blob/v2.1/doc/status.html#L100>`_
-- Linux on x86_64 is unaffected but `Linux on aarch64 is
<https://gitlab.labs.nic.cz/knot/knot-resolver/issues/216>`_.

.. code-block:: bash

   $ git clone --recursive https://gitlab.labs.nic.cz/knot/knot-resolver.git

Dependencies
------------

.. warning:: Section *Dependencies* is not up-to-date. Also, individual modules
   might have additional build or runtime dependencies.

The following is a list of dependencies needed to build and run Knot Resolver.


.. csv-table::
   :header: "Requirement", "Required by", "Notes"

   "ninja", "*all*", "*(build_only)*"
   "meson >= 0.47", "*all*", "*(build only)* [#]_"
   "C and C++ compiler", "*all*", "*(build only)* [#]_"
   "`pkg-config`_", "*all*", "*(build only)* [#]_"
   "libknot_ 2.7.6+", "*all*", "Knot DNS libraries"
   "LuaJIT_ 2.0+", "*all*", "Embedded scripting language."
   "libuv_ 1.7+", "*all*", "Multiplatform I/O and services."
   "lmdb", "*all*", "Memory-mapped database for cache"
   "GnuTLS", "*all*", "TLS"

There are also *optional* packages that enable specific functionality in Knot
Resolver, they are useful mainly for developers to build documentation and
tests.

.. csv-table::
   :header: "Optional", "Needed for", "Notes"

   "`lua-http`_", "``modules/http``", "HTTP/2 client/server for Lua."
   "luasocket_", "``trust anchors, modules/stats``", "Sockets for Lua."
   "luasec_", "``trust anchors``", "TLS for Lua."
   "cmocka_", "``unit tests``", "Unit testing framework."
   "Doxygen_", "``documentation``", "Generating API documentation."
   "Sphinx_ and sphinx_rtd_theme_", "``documentation``", "Building this
   HTML/PDF documentation."
   "breathe_", "``documentation``", "Exposing Doxygen API doc to Sphinx."
   "libsystemd_ >= 227", "``daemon``", "Systemd socket activation support."
   "libprotobuf_ 3.0+", "``modules/dnstap``", "Protocol Buffers support for
   dnstap_."
   "`libprotobuf-c`_ 1.0+", "``modules/dnstap``", "C bindings for Protobuf."
   "libfstrm_ 0.2+", "``modules/dnstap``", "Frame Streams data transport
   protocol."
   "luacheck_", "``lint-lua``", "Syntax and static analysis checker for Lua."
   "`clang-tidy`_", "``lint-c``", "Syntax and static analysis checker for C."
   "luacov_", "``check-config``", "Code coverage analysis for Lua modules."

.. [#] If ``meson >= 0.47`` isn't available for your distro, check backports
   repository oor use python pip to install it.
.. [#] Requires C99, ``__attribute__((cleanup))`` and ``-MMD -MP`` for
   dependency file generation. GCC, Clang and ICC are supported.
.. [#] You can use variables ``<dependency>_CFLAGS`` and ``<dependency>_LIBS``
   to configure dependencies manually (i.e. ``libknot_CFLAGS`` and
   ``libknot_LIBS``).
.. [#] libuv 1.7 brings SO_REUSEPORT support that is needed for multiple forks.
   libuv < 1.7 can be still used, but only in single-process mode. Use
   :ref:`different method <daemon-reuseport>` for load balancing.

Packaged dependencies
~~~~~~~~~~~~~~~~~~~~~

.. note:: TODO mention home:CZ-NIC:knot-reslver-build here

Most of the dependencies can be resolved from packages, here's an overview for
several platforms.

* **Debian** (since *sid*) - current stable doesn't have libknot and libuv,
  which must be installed from sources.

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
* **openSUSE** - there is an `experimental package
  <https://build.opensuse.org/package/show/server:dns/knot-resolver>`_.
* **FreeBSD** - when installing from ports, all dependencies will install
  automatically, corresponding to the selected options.
* **NetBSD** - unknown.
* **OpenBSD** - unknown.
* **Mac OS X** - the dependencies can be found through `Homebrew
  <http://brew.sh/>`_.

.. code-block:: bash

   brew install pkg-config libuv luajit cmocka

Compilation
-----------

When installing into custom prefix during development / testing, using static
library is recommended to avoid issues with loading a shared library.

.. code-block:: bash

   $ meson build_dev --prefix=/tmp/kr --default-library=static
   $ ninja -C build_dev
   $ ninja install -C build_dev

Meson performs the build in the specified directory (``build_dev/`` in this
case) and doesn't pollute the source tree.  This allows you to have multiple
build roots with different build configurations at the same time.

Build options
~~~~~~~~~~~~~

It's possible to change the compilation with build options. These are useful to
packagers or developers who wish to customize the daemon behaviour, run
extended test suites etc.  By default, these are all set to sensible values.

For complete list of build options create a build directory and run:

.. code-block:: bash

   $ meson build_info
   $ meson configure build_info

To customize project build option, use ``-Doption=value`` when creating
a build directory:

.. code-block:: bash

   $ meson build_doc -Ddoc=enabled

Running tests
~~~~~~~~~~~~~

To run in-tree tests:

.. code-block:: bash

   $ ninja -C build_dev
   $ meson test --no-suite postinstall -C build_dev

More comprehensive tests require you to install kresd before running the test
suite.  To run all available tests (also see ``extra_tests`` build option),
use:

.. code-block:: bash

   $ ninja -C build_dev
   $ ninja install -C build_dev
   $ meson test -C build_dev

Packagers
~~~~~~~~~

Recommended switches for ``meson build_pkg``:

* ``--buildtype=release`` turns on optimalizations, turns off asserts (override
  with ``-Db_ndebug=false`` if desired)
* ``--unity=on`` faster builds, see `Unity builds
  <https://mesonbuild.com/Unity-builds.html>`_
* ``--prefix=/usr`` to customize
  prefix, other directories can be set in a similar fashion, see ``meson setup
  --help``
* ``-Dsystemd_unit_files=enabled`` for systemd unit files with socket activation
  support. Alternately, for systemd < 227, use ``nosocket``. If you need to
  customize unit files, use drop-in files.
* ``-Ddoc=enabled`` for offline html documentation
* ``-Dclient=enabled`` to force build of kresc
* ``-Dunit_tests=enabled`` to force build of unit tests

If the target distro has externally managed DNSSEC trust anchors or root hints:

* ``-Dkeyfile_default=/usr/share/dns/root.key``
* ``-Droot_hints=/usr/share/dns/root.hints``

In case you want to have automatically managed DNSSEC trust anchors instead,
set the following and make sure both ``root.keys`` (check default
``keyfile_default`` path in summary) and its parent directory will be writable
by kresd process.

* ``-Dmanaged_ta=enabled``

Customizing compiler flags
~~~~~~~~~~~~~~~~~~~~~~~~~~

If you'd like to use custom compiler flags, see meson's `built-in options
<https://mesonbuild.com/Builtin-options.html>`_. You might be interested in
``c_args``, ``c_link_args``. For hardening, it's also possible to use
``b_pie``.

Docker image
------------

Visit `hub.docker.com/r/cznic/knot-resolver
<https://hub.docker.com/r/cznic/knot-resolver/>`_ for instructions how to run
the container.

For development, it's possible to build the container directly from your git tree:

.. code-block:: bash

   $ docker build -t knot-resolver .


.. _Docker images: https://hub.docker.com/r/cznic/knot-resolver
.. _libuv: https://github.com/libuv/libuv
.. _LuaJIT: http://luajit.org/luajit.html
.. _Doxygen: https://www.stack.nl/~dimitri/doxygen/manual/index.html
.. _breathe: https://github.com/michaeljones/breathe
.. _Sphinx: http://sphinx-doc.org/
.. _sphinx_rtd_theme: https://pypi.python.org/pypi/sphinx_rtd_theme
.. _pkg-config: https://www.freedesktop.org/wiki/Software/pkg-config/
.. _libknot: https://gitlab.labs.nic.cz/knot/knot-dns
.. _cmocka: https://cmocka.org/
.. _luasec: https://luarocks.org/modules/brunoos/luasec
.. _luasocket: https://luarocks.org/modules/luarocks/luasocket
.. _lua-http: https://luarocks.org/modules/daurnimator/http
.. _boot2docker: http://boot2docker.io/
.. _deckard: https://gitlab.labs.nic.cz/knot/deckard
.. _libsystemd: https://www.freedesktop.org/wiki/Software/systemd/
.. _dnstap: http://dnstap.info/
.. _libprotobuf: https://developers.google.com/protocol-buffers/
.. _libprotobuf-c: https://github.com/protobuf-c/protobuf-c/wiki
.. _libfstrm: https://github.com/farsightsec/fstrm
.. _luacheck: http://luacheck.readthedocs.io
.. _clang-tidy: http://clang.llvm.org/extra/clang-tidy/index.html
.. _luacov: https://keplerproject.github.io/luacov/
.. _lcov: http://ltp.sourceforge.net/coverage/lcov.php
