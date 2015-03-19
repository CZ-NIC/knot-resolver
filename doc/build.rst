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
   "libknot_ 2.0+", "*all*", "Knot DNS library."

There are also *optional* packages that enable specific functionality in Knot DNS Resolver, apart from the `libuv_` and `GCCGO`_, they are useful mainly for developers to build documentation and tests.

.. csv-table::
   :header: "Requirement", "Required by", "Notes"

   "libuv_ 1.0+", "``daemon``", "Multiplatform I/O and services."
   "cmocka_", "``unit tests``", "Unit testing framework."
   "Python_", "``integration tests``", "For scripting tests, C header files are required (``python-dev``)"
   "GCCGO_",  "``modules/go``", "For building Go modules, see modules documentation."
   "Doxygen_", "``documentation``", "Generating API documentation."
   "Sphinx_", "``documentation``", "Building this HTML/PDF documentation."
   "breathe_", "``documentation``", "Exposing Doxygen API doc to Sphinx."

.. [#] Requires C99, ``__attribute__((cleanup))`` and ``-MMD -MP`` for dependency file generation. GCC, Clang and ICC are supported.
.. [#] You can use variables ``<dependency>_CFLAGS`` and ``<dependency>_LIBS`` to configure dependencies manually (i.e. ``libknot_CFLAGS`` and ``libknot_LIBS``).

Docker image
~~~~~~~~~~~~

Docker images require only either Linux or a Linux VM (see boot2docker_ on OS X).

.. code-block:: bash

   $ docker run cznic/knot-resolver

See the `Docker images`_ page for more information and options.
You can hack on the container by changing the container entrypoint to shell like:

.. code-block:: bash

   $ docker run -it --entrypoint=/bin/bash cznic/knot-resolver

Building from sources 
~~~~~~~~~~~~~~~~~~~~~

The Knot DNS Resolver depends on the development version of the Knot DNS library, and a reasonably recent version of `libuv`.
Several dependencies may not be in the packages yet, the script pulls and installs all dependencies in a chroot.

.. code-block:: bash

   $ make info # See what's missing

You can avoid rebuilding dependencies by specifying `BUILD_IGNORE` variable, see the Dockerfile_ for example.
Usually you only really need to rebuild `libknot`.

.. code-block:: bash

   $ export FAKEROOT="${HOME}/.local"
   $ export PKG_CONFIG_PATH="${FAKEROOT}/lib/pkgconfig"
   $ export BUILD_IGNORE="..." # Ignore installed dependencies
   $ ./scripts/bootstrap-depends.sh ${FAKEROOT}


.. note:: The build system relies on `pkg-config`_ to find dependencies.
   You can override it to force custom versions of the software by environment variables.

   .. code-block:: bash

      $ make check libknot_CFLAGS="-I/opt/include" libknot_LIBS="-L/opt/lib -lknot -lknot-int -ldnssec"

When you have all the dependencies ready, you can build, test and install.

.. code-block:: bash

   $ make
   $ make check
   $ make install

Alternatively you can build only specific parts of the project, i.e. ``library``.

.. code-block:: bash

   $ make lib
   $ make lib-install

.. note:: Documentation is not built by default, run ``make doc`` to build it.

Building extras
~~~~~~~~~~~~~~~

The project can be built with code coverage tracking using the ``COVERAGE=1`` variable.

.. _Docker images: https://registry.hub.docker.com/u/cznic/knot-resolver
.. _libuv: https://github.com/libuv/libuv
.. _MSVC: https://msdn.microsoft.com/en-us/vstudio/hh386302.aspx
.. _MinGW: http://www.mingw.org/
.. _Dockerfile: https://registry.hub.docker.com/u/cznic/knot-resolver/dockerfile/

.. _GCCGO: https://golang.org/doc/install/gccgo
.. _Doxygen: http://www.stack.nl/~dimitri/doxygen/manual/index.html
.. _breathe: https://github.com/michaeljones/breathe
.. _Sphinx: http://sphinx-doc.org/
.. _GNU Make: http://www.gnu.org/software/make/
.. _pkg-config: http://www.freedesktop.org/wiki/Software/pkg-config/
.. _libknot: https://gitlab.labs.nic.cz/labs/knot
.. _cmocka: https://cmocka.org/
.. _Python: https://www.python.org/

.. _boot2docker: http://boot2docker.io/