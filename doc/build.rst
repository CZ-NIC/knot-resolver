Building project
================

The resolver isn't yet available in the repositories, so you can either build it from sources or use
official `Docker images`_.

Platform considerations
-----------------------

.. csv-table::
   :header: "Project", "Platforms", "Compatibility notes"

   "``daemon``", "UNIX-like [#]_, Microsoft Windows", "C99, libuv_ provides portable I/O"
   "``library``", "UNIX-like, Microsoft Windows [#]_ ", "MSVC_ not supported, needs MinGW_"
   "``modules``", "*varies*", ""
   "``tests/unit``", "*equivalent to library*", ""
   "``tests/integration``", "UNIX-like", "Depends on library injection (see [2]_)"

.. [#] Known to be running (not exclusively) on FreeBSD, Linux and OS X.
.. [#] Modules are not supported yet, as the PE/DLL loading is different. Library injection is working with ELF *(or Mach-O flat namespace)* only.

Requirements
------------

The following is a list of software required to build Knot DNS Resolver from sources.

.. csv-table::
   :header: "Requirement", "Required by", "Notes"

   "`GNU Make`_ 3.80+", "*all*", "*(build only)*"
   "`pkg-config`_", "*all*", "*(build only)* [#]_"
   "C compiler", "*all*", "*(build only)* [#]_"
   "libknot_ 2.0+", "*all*", "Knot DNS library (requires autotools, GnuTLS and Jansson)."
   "LuaJIT_ 2.0+", "``daemon``", "Embedded scripting language."
   "libuv_ 1.7+", "``daemon``", "Multiplatform I/O and services (libuv_ 1.0 with limitations [#]_)."

There are also *optional* packages that enable specific functionality in Knot DNS Resolver, they are useful mainly for developers to build documentation and tests.

.. csv-table::
   :header: "Optional", "Needed for", "Notes"

   "luasocket_", "``trust anchors, modules/stats``", "Sockets for Lua."
   "luasec_", "``trust anchors``", "TLS for Lua."
   "libmemcached_", "``modules/memcached``", "To build memcached backend module."
   "hiredis_", "``modules/redis``", "To build redis backend module."
   "Go_ 1.5+", "``modules``", "Build modules written in Go."
   "cmocka_", "``unit tests``", "Unit testing framework."
   "Python_", "``integration tests``", "For test scripts."
   "Doxygen_", "``documentation``", "Generating API documentation."
   "Sphinx_", "``documentation``", "Building this HTML/PDF documentation."
   "breathe_", "``documentation``", "Exposing Doxygen API doc to Sphinx."

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
* **RHEL/CentOS** - unknown.
* **openSUSE** - there is an `experimental package <https://build.opensuse.org/package/show/server:dns/knot-resolver>`_.
* **RHEL** - unknown.
* **FreeBSD** - unknown.
* **NetBSD** - unknown.
* **OpenBSD** - unknown.
* **Mac OS X** - most of the dependencies can be found through `Homebrew <http://brew.sh/>`_, with the exception of libknot.

.. code-block:: bash

   brew install pkg-config libuv luajit cmocka

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

Building from sources 
---------------------

The Knot DNS Resolver depends on the the Knot DNS library, recent version of libuv_, and LuaJIT_.

.. code-block:: bash

   $ make info # See what's missing

When you have all the dependencies ready, you can build and install.

.. code-block:: bash

   $ make PREFIX="/usr/local"
   $ make install

.. note:: Always build with ``PREFIX`` if you want to install, as it is hardcoded in the executable for module search path. If you build the binary with ``-DNDEBUG``, verbose logging will be disabled as well.

Alternatively you can build only specific parts of the project, i.e. ``library``.

.. code-block:: bash

   $ make lib
   $ make lib-install

.. note:: Documentation is not built by default, run ``make doc`` to build it.

Building with security compiler flags
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Knot DNS Resolver enables certain `security compile-time flags <https://wiki.debian.org/Hardening#Notes_on_Memory_Corruption_Mitigation_Methods>`_ that do not affect performance.
You can add more flags to the build by appending them to `CFLAGS` variable, e.g. ``make CFLAGS="-fstack-protector"``.

  .. csv-table::
   :header: "Method", "Status", "Notes"

   "-fstack-protector", "*disabled*", "(must be specifically enabled in CFLAGS)"
   "-D_FORTIFY_SOURCE=2", "**enabled**", ""
   "-pie", "**enabled**", "enables ASLR for kresd (disable with ``make HARDENING=no``)"
   "RELRO", "**enabled**", "full [#]_"

You can also disable ELF hardening when it's unsupported with ``make HARDENING=no``.

.. [#] See `checksec.sh <http://www.trapkit.de/tools/checksec.html>`_

Building for packages
~~~~~~~~~~~~~~~~~~~~~

The build system supports both DESTDIR_ and `amalgamated builds <https://www.sqlite.org/amalgamation.html>`_.

.. code-block:: bash

   $ make install DESTDIR=/tmp/stage # Staged install
   $ make all install AMALG=yes # Amalgamated build

.. note:: Amalgamated build assembles everything in one source file and compiles it. It is useful for packages, as the compiler sees the whole program and is able to produce a smaller and faster binary. On the other hand, it complicates debugging.

Default paths
~~~~~~~~~~~~~

The default installation follows FHS with several custom paths for configuration and modules.
All paths are prefixed with ``PREFIX`` variable by default if not specified otherwise.

  .. csv-table::
   :header: "Component", "Variable", "Default", "Notes"

   "library", "``LIBDIR``", "``$(PREFIX)/lib``", "Built statically."
   "daemon",  "``BINDIR``", "``$(PREFIX)/bin``", ""
   "configuration", "``ETCDIR``", "``$(PREFIX)/etc/kresd``", "Configuration file, templates."
   "modules", "``MODULEDIR``", "``$(LIBDIR)/kdns_modules``", "[#]_"
   "work directory", "", "``$(PREFIX)/var/run/kresd``", "Run directory for daemon."

.. [#] Users may install additional modules in ``~/.local/lib/kdns_modules`` or in the rundir of a specific instance.

.. note:: Each module is self-contained and may install additional bundled files within ``$(MODULEDIR)/$(modulename)``. These files should be read-only, non-executable.

Building dependencies
~~~~~~~~~~~~~~~~~~~~~

Several dependencies may not be in the packages yet, the script pulls and installs all dependencies in a chroot.
You can avoid rebuilding dependencies by specifying `BUILD_IGNORE` variable, see the Dockerfile_ for example.
Usually you only really need to rebuild libknot_.

.. code-block:: bash

   $ export FAKEROOT="${HOME}/.local"
   $ export PKG_CONFIG_PATH="${FAKEROOT}/lib/pkgconfig"
   $ export BUILD_IGNORE="..." # Ignore installed dependencies
   $ ./scripts/bootstrap-depends.sh ${FAKEROOT}

.. note:: The build system relies on `pkg-config`_ to find dependencies.
   You can override it to force custom versions of the software by environment variables.

   .. code-block:: bash

      $ make libknot_CFLAGS="-I/opt/include" libknot_LIBS="-L/opt/lib -lknot -lknot-int -ldnssec"

.. warning:: If the dependencies lie outside of library search path, you need to add them somehow.
   Try ``LD_LIBRARY_PATH`` on Linux/BSD, and ``DYLD_FALLBACK_LIBRARY_PATH`` on OS X.
   Otherwise you need to add the locations to linker search path.

Building extras
~~~~~~~~~~~~~~~

The project can be built with code coverage tracking using the ``COVERAGE=1`` variable.

Running unit and integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The unit tests require cmocka_ and are executed with ``make check``.

The integration tests use Deckard, the `DNS test harness <deckard>`_.

.. code-block:: bash

	$  make check-integration

Note that the daemon and modules must be installed first before running integration tests, the reason is that the daemon
is otherwise unable to find and load modules.

Read the `documentation <deckard_doc>`_ for more information about requirements, how to run it and extend it.

.. _Docker images: https://registry.hub.docker.com/u/cznic/knot-resolver
.. _libuv: https://github.com/libuv/libuv
.. _MSVC: https://msdn.microsoft.com/en-us/vstudio/hh386302.aspx
.. _MinGW: http://www.mingw.org/
.. _Dockerfile: https://registry.hub.docker.com/u/cznic/knot-resolver/dockerfile/

.. _Lua: http://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _Go: https://golang.org
.. _libmemcached: http://libmemcached.org/libMemcached.html
.. _hiredis: https://github.com/redis/hiredis
.. _Doxygen: http://www.stack.nl/~dimitri/doxygen/manual/index.html
.. _breathe: https://github.com/michaeljones/breathe
.. _Sphinx: http://sphinx-doc.org/
.. _GNU Make: http://www.gnu.org/software/make/
.. _pkg-config: http://www.freedesktop.org/wiki/Software/pkg-config/
.. _libknot: https://gitlab.labs.nic.cz/labs/knot
.. _cmocka: https://cmocka.org/
.. _Python: https://www.python.org/
.. _luasec: https://luarocks.org/modules/luarocks/luasec
.. _luasocket: https://luarocks.org/modules/luarocks/luasocket

.. _boot2docker: http://boot2docker.io/

.. _deckard: https://gitlab.labs.nic.cz/knot/deckard
.. _deckard_doc: https://gitlab.labs.nic.cz/knot/resolver/blob/master/tests/README.rst

.. _DESTDIR: https://www.gnu.org/prep/standards/html_node/DESTDIR.html
