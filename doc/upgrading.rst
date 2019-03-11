*********
Upgrading
*********

This section summarizes steps required for upgrade to newer Knot Resolver versions.
We advise users to also read :ref:`release_notes` for respective versions.

.. _upgrade-from-3-to-4:

3.x to 4.x
==========

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


.. _upgrade-from-2-to-3:

2.x to 3.x
==========

Users
-----

* Module :ref:`mod-hints` has option :func:`hints.use_nodata` enabled by default,
  which is what most users expect. Add ``hints.use_nodata(false)`` to your config
  to revert to the old behavior.
* Modules ``cookie`` and ``version`` were removed.
  Please remove relevant configuration lines with ``modules.load()`` and ``modules =``
  from configuration file.
* Valid configuration must open cache using ``cache.open()`` or ``cache.size =``
  before executing cache operations like ``cache.clear()``.
  (Older versions were silently ignoring such cache operations.)

Packagers & Developers
----------------------

* Knot DNS >= 2.7.2 is required.

Module changes
~~~~~~~~~~~~~~

* API for Lua modules was refactored, please see :ref:`significant-lua-changes`.
* New layer was added: ``answer_finalize``.
* ``kr_request`` keeps ``::qsource.packet`` beyond the ``begin`` layer.
* ``kr_request::qsource.tcp`` renamed to ``::qsource.flags.tcp``.
* ``kr_request::has_tls`` renamed to ``::qsource.flags.tls``.
* ``kr_zonecut_add()``, ``kr_zonecut_del()`` and ``kr_nsrep_sort()`` changed
  parameters slightly.
