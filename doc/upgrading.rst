*********
Upgrading
*********

.. _upgrade-from-3-to-4:

Upgrade from 3.x to 4.x
=======================

Users
-----

* DNSSEC validation is now turned on by default. If you need to disable it, see
  :ref:`dnssec-config`.
* In case you are using your own custom modules, move them to the new module
  location. The exact location depends on your distribution. Generally, modules previously
  in ``/usr/lib/kdns_modules`` should be moved to ``/usr/lib/knot-resolver/kres_modules``.

Packagers & Developers
----------------------

* Knot DNS >= 2.8 is required.
* meson >= 0.46 and ninja is required.
* meson build system is now used for compiling the project. For instructions, see
  the :ref:`build`. Packagers should pay attention to section :ref:`packaging`
  for information about systemd unit files and trust anchors.
* Embedding LMDB is no longer supported, lmdb is now required as an external dependency.
* Trust anchors file from upstream is installed and used as default unless you
  override ``keyfile_default`` during build.

Module changes
~~~~~~~~~~~~~~

* Default module location has changed from ``{libdir}/kdns_modules`` to
  ``{libdir}/knot-resolver/kres_modules``. Modules are now in the lua namespace
  ``kres_modules.*``.
* ``kr_straddr_split()`` API has changed.


Upgrade from 2.x to 3.x
=======================

Users
-----

* ``hints.use_nodata(true)`` by default.
* In case you wrote custom Lua modules, please consult :ref:`significant-lua-changes`.
* Removed modules: ``cookie`` (temporarily) and ``version`` (permanently).

Packagers & Developers
----------------------

* Knot DNS >= 2.7.2 is required.
* cache: fail lua operations if cache isn't open yet (!639)
  By default cache is opened *after* reading the configuration,
  and older versions were silently ignoring cache operations.
  Valid configuration must open cache using `cache.open()` or `cache.size =`
  before executing cache operations like `cache.clear()`.

Module changes
~~~~~~~~~~~~~~

* New layer was added: ``answer_finalize``.
* ``kr_request`` keeps ``::qsource.packet`` beyond the ``begin`` layer.
* ``kr_request::qsource.tcp`` renamed to ``::qsource.flags.tcp``.
* ``kr_request::has_tls`` renamed to ``::qsource.flags.tls``.
* ``kr_zonecut_add()``, ``kr_zonecut_del()`` and ``kr_nsrep_sort()`` changed
  parameters slightly.
