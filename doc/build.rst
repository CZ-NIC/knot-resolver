.. SPDX-License-Identifier: GPL-3.0-or-later

.. _build:

Building from sources
=====================

.. note:: Latest up-to-date packages for various distribution can be obtained
   from web `<https://knot-resolver.cz/download/>`_.

Knot Resolver is written for UNIX-like systems using modern C standards.
Beware that some 64-bit systems with LuaJIT 2.1 may be affected by
`a problem <https://github.com/LuaJIT/LuaJIT/blob/v2.1.0-beta3/doc/status.html#L100>`_
-- Linux on x86_64 is unaffected but `Linux on aarch64 is
<https://gitlab.nic.cz/knot/knot-resolver/issues/216>`_.

.. code-block:: bash

   $ git clone --recursive https://gitlab.nic.cz/knot/knot-resolver.git

Building with apkg
------------------

Knot Resolver uses `apkg tool <https://pkg.labs.nic.cz/pages/apkg/>`_ for upstream packaging.
It allows build packages localy for supported distributions, which it then installs.
``apkg`` also takes care of dependencies itself.

First, you need to install and setup ``apkg``.

.. code-block:: bash

   $ pip3 install apkg
   $ apkg system-setup

Clone and change dir to ``knot-resolver`` git repository.

.. code-block:: bash

   $ git clone --recursive https://gitlab.nic.cz/knot/knot-resolver.git
   $ cd knot-resolver

.. tip:: The ``apkg status`` command can be used to find out some useful information, such as whether the current distribution is supported.

When ``apkg`` is ready, a package can be build and installed.

.. code-block:: bash

   # takes care of dependencies
   apkg build-dep

   # build package
   apkg build

   # (build and) install package, builds package when it is not already built
   apkg install

After that Knot Resolver should be installed.

Building with Meson
-------------------

Knot Resolver uses `Meson Build system <https://mesonbuild.com/>`_.
Shell snippets below should be sufficient for basic usage
but users unfamiliar with Meson might want to read introductory
article `Using Meson <https://mesonbuild.com/Quick-guide.html>`_.


Dependencies
~~~~~~~~~~~~

.. note:: This section lists basic requirements. Individual modules
   might have additional build or runtime dependencies.

The following dependencies are needed to build and run Knot Resolver with core functions:

.. csv-table::
   :header: "Requirement", "Notes"

   "ninja", "*build only*"
   "meson >= 0.49", "*build only* [#]_"
   "C and C++ compiler", "*build only* [#]_"
   "`pkg-config`_", "*build only* [#]_"
   "libknot_ 3.0.2+", "Knot DNS libraries"
   "LuaJIT_ 2.0+", "Embedded scripting language"
   "libuv_ 1.7+", "Multiplatform I/O and services"
   "lmdb", "Memory-mapped database for cache"
   "GnuTLS", "TLS"

Additional dependencies are needed to build and run Knot Resolver with ``manager``:

.. csv-table::
   :header: "Requirement", "Notes"

   "python3_ >=3.6.8", "Python language interpreter"
   "Jinja2_", "Template engine for Python"
   "PyYAML_", "YAML framework for Python"
   "aiohttp_", "HTTP Client/Server for Python."
   "prometheus-client_", "Prometheus client for Python"
   "typing-extensions_", "Compatibility module for Python"


There are also *optional* packages that enable specific functionality in Knot
Resolver:

.. TODO cqueues is really used on multiple places, sometimes indirectly

.. csv-table::
   :header: "Optional", "Needed for", "Notes"

   "nghttp2_", "``daemon``", "DNS over HTTPS support."
   "libsystemd_", "``daemon``", "Systemd watchdog support."
   "`libcap-ng`_", "``daemon``", "Linux capabilities: support dropping them."
   "`lua-basexx`_", "``config tests``", "Number base encoding/decoding for Lua."
   "`lua-http`_", "``modules/http``", "HTTP/2 client/server for Lua."
   "`lua-cqueues`_", "some lua modules", ""
   "cmocka_", "``unit tests``", "Unit testing framework."
   "Doxygen_", "``documentation``", "Generating API documentation."
   "Sphinx_, sphinx-tabs_ and sphinx_rtd_theme_", "``documentation``", "Building this
   documentation."
   "Texinfo_", "``documentation``", "Generating this documentation in Info
   format."
   "breathe_", "``documentation``", "Exposing Doxygen API doc to Sphinx."
   "libprotobuf_ 3.0+", "``modules/dnstap``", "Protocol Buffers support for
   dnstap_."
   "`libprotobuf-c`_ 1.0+", "``modules/dnstap``", "C bindings for Protobuf."
   "libfstrm_ 0.2+", "``modules/dnstap``", "Frame Streams data transport
   protocol."
   "luacheck_", "``lint-lua``", "Syntax and static analysis checker for Lua."
   "`clang-tidy`_", "``lint-c``", "Syntax and static analysis checker for C."
   "luacov_", "``check-config``", "Code coverage analysis for Lua modules."

.. [#] If ``meson >= 0.49`` isn't available for your distro, check backports
   repository or use python pip to install it.
.. [#] Requires ``__attribute__((cleanup))`` and ``-MMD -MP`` for
   dependency file generation. We test GCC and Clang, and ICC is likely to work as well.
.. [#] You can use variables ``<dependency>_CFLAGS`` and ``<dependency>_LIBS``
   to configure dependencies manually (i.e. ``libknot_CFLAGS`` and
   ``libknot_LIBS``).

.. note:: Some build dependencies can be found in
   `home:CZ-NIC:knot-resolver-build
   <https://build.opensuse.org/project/show/home:CZ-NIC:knot-resolver-build>`_.

On reasonably new systems most of the dependencies can be resolved from packages,
here's an overview for several platforms.

* **Debian/Ubuntu** - Current stable doesn't have new enough Meson
  and libknot. Use repository above or build them yourself. Fresh list of dependencies can be found in `Debian control file in our repo <https://gitlab.nic.cz/knot/knot-resolver/blob/master/distro/deb/control>`_, search for "Build-Depends".

* **CentOS/Fedora/RHEL/openSUSE** - Fresh list of dependencies can be found in `RPM spec file in our repo <https://gitlab.nic.cz/knot/knot-resolver/blob/master/distro/rpm/knot-resolver.spec>`_, search for "BuildRequires".

* **FreeBSD** - when installing from ports, all dependencies will install
  automatically, corresponding to the selected options.
* **Mac OS X** - the dependencies can be obtained from `Homebrew formula <https://formulae.brew.sh/formula/knot-resolver>`_.

Compilation
~~~~~~~~~~~

Folowing meson command creates new build directory named ``build_dir``, configures installation path to ``/tmp/kr`` and enables static build (to allow installation to non-standard path).
You can also configure some :ref:`build-options`, in this case enable ``manager``, which is disabled by default.

.. code-block:: bash

   $ meson build_dir --prefix=/tmp/kr --default-library=static -Dmanager=enabled -Dpython.install_env=auto

.. note::

   For the ``manager``, it is recommended to set ``python.install_env`` option to ``auto`` or ``env``.
   Otherwise, python package may not be installed in the correct packages or virtual environment.
   See more on `meson:python-module <https://mesonbuild.com/Builtin-options.html#python-module>`_.

After that it is possible to build and install Knot Resolver.

.. code-block:: bash

   # build Knot Resolver
   $ ninja -C build_dir

   # install Knot Resolver into the previously configured '/tmp/kr' path
   $ ninja install -C build_dir

At this point you can execute the newly installed binary using path ``/tmp/kr/sbin/kresd``.

.. note:: When compiling on OS X, creating a shared library is currently not
   possible when using luajit package from Homebrew due to `#37169
   <https://github.com/Homebrew/homebrew-core/issues/37169>`_.

.. _build-options:

Build options
~~~~~~~~~~~~~

It's possible to change the compilation with build options. These are useful to
packagers or developers who wish to customize the daemon behaviour, run
extended test suites etc.  By default, these are all set to sensible values.

For complete list of build options create a build directory and run:

.. code-block:: bash

   $ meson build_dir
   $ meson configure build_dir

To customize project build options, use ``-Doption=value`` when creating
a build directory:

.. code-block:: bash

   $ meson build_dir -Ddoc=enabled

... or change options in an already existing build directory:

.. code-block:: bash

   $ meson configure build_dir -Ddoc=enabled


.. _build-custom-flags:

Customizing compiler flags
~~~~~~~~~~~~~~~~~~~~~~~~~~

If you'd like to use customize the build, see meson's `built-in options
<https://mesonbuild.com/Builtin-options.html>`_. For hardening, see ``b_pie``.

For complete control over the build flags, use ``--buildtype=plain`` and set
``CFLAGS``, ``LDFLAGS`` when creating the build directory with ``meson``
command.

.. include:: ../tests/README.rst

.. _build-html-doc:

Documentation
-------------

To check for documentation dependencies and allow its installation, use
``-Ddoc=enabled``. The documentation doesn't build automatically. Instead,
target ``doc`` must be called explicitly.

.. code-block:: bash

   $ meson build_dir -Ddoc=enabled
   $ ninja -C build_dir doc

Tarball
-------

Released tarballs are available from `<https://knot-resolver.cz/download/>`_

To make a release tarball from git, use the following command. The

.. code-block:: bash

   $ ninja -C build_dir dist

It's also possible to make a development snapshot tarball:

.. code-block:: bash

   $ ./scripts/make-archive.sh

.. _packaging:

Packaging
---------

Recommended build options for packagers:

* ``--buildtype=release`` for default flags (optimization, asserts, ...). For complete control over flags, use ``plain`` and see :ref:`build-custom-flags`.
* ``--prefix=/usr`` to customize
  prefix, other directories can be set in a similar fashion, see ``meson setup
  --help``
* ``-Dsystemd_files=enabled`` for systemd unit files
* ``-Ddoc=enabled`` for offline documentation (see :ref:`build-html-doc`)
* ``-Dinstall_kresd_conf=enabled`` to install default config file
* ``-Dmanager=enabled`` to force build of the manager and its features
* ``-Dclient=enabled`` to force build of kresc
* ``-Dunit_tests=enabled`` to force build of unit tests

Systemd
~~~~~~~

It's recommended to use the upstream system unit files. If any customizations
are required, drop-in files should be used, instead of patching/changing the
unit files themselves.

To install systemd unit files, use the ``-Dsystemd_files=enabled`` build option.

To support enabling services after boot, you must also link ``kresd.target`` to
``multi-user.target.wants``:

.. code-block:: bash

   ln -s ../kresd.target /usr/lib/systemd/system/multi-user.target.wants/kresd.target

Trust anchors
~~~~~~~~~~~~~

If the target distro has externally managed (read-only) DNSSEC trust anchors
or root hints use this:

* ``-Dkeyfile_default=/usr/share/dns/root.key``
* ``-Droot_hints=/usr/share/dns/root.hints``
* ``-Dmanaged_ta=disabled``

In case you want to have automatically managed DNSSEC trust anchors instead,
set ``-Dmanaged_ta=enabled`` and make sure both ``keyfile_default`` file and
its parent directories are writable by kresd process (after package installation!).

Docker image
------------

Visit `hub.docker.com/r/cznic/knot-resolver
<https://hub.docker.com/r/cznic/knot-resolver/>`_ for instructions how to run
the container.

For development, it's possible to build the container directly from your git tree:

.. code-block:: bash

   $ docker build -t knot-resolver .


.. _libuv: https://github.com/libuv/libuv
.. _LuaJIT: http://luajit.org/luajit.html
.. _Doxygen: https://www.doxygen.nl/manual/index.html
.. _breathe: https://github.com/michaeljones/breathe
.. _Sphinx: http://sphinx-doc.org/
.. _sphinx-tabs: https://sphinx-tabs.readthedocs.io
.. _sphinx_rtd_theme: https://pypi.python.org/pypi/sphinx_rtd_theme
.. _Texinfo: https://www.gnu.org/software/texinfo/
.. _pkg-config: https://www.freedesktop.org/wiki/Software/pkg-config/
.. _libknot: https://gitlab.nic.cz/knot/knot-dns
.. _cmocka: https://cmocka.org/
.. _lua-basexx: https://github.com/aiq/basexx
.. _lua-http: https://luarocks.org/modules/daurnimator/http
.. _lua-cqueues: https://25thandclement.com/~william/projects/cqueues.html
.. _deckard: https://gitlab.nic.cz/knot/deckard
.. _nghttp2: https://nghttp2.org/
.. _libsystemd: https://www.freedesktop.org/wiki/Software/systemd/
.. _`libcap-ng`: https://people.redhat.com/sgrubb/libcap-ng/
.. _dnstap: http://dnstap.info/
.. _libprotobuf: https://developers.google.com/protocol-buffers/
.. _libprotobuf-c: https://github.com/protobuf-c/protobuf-c/wiki
.. _libfstrm: https://github.com/farsightsec/fstrm
.. _luacheck: http://luacheck.readthedocs.io
.. _clang-tidy: http://clang.llvm.org/extra/clang-tidy/index.html
.. _luacov: https://lunarmodules.github.io/luacov/
.. _lcov: http://ltp.sourceforge.net/coverage/lcov.php
.. _python3: https://www.python.org/
.. _Jinja2: https://jinja.palletsprojects.com/
.. _PyYAML: https://pyyaml.org/
.. _aiohttp: https://docs.aiohttp.org/
.. _prometheus-client: https://github.com/prometheus/client_python
.. _typing-extensions: https://pypi.org/project/typing-extensions/
