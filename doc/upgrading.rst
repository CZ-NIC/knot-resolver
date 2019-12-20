*********
Upgrading
*********

This section summarizes steps required for upgrade to newer Knot Resolver versions.
We advise users to also read :ref:`release_notes` for respective versions.

4.x to 5.x
==========

Configuration file
------------------

* ``net.listen()`` throws an error if it fails to bind. Use ``freebind=true`` option
  to bind to nonlocal addresses.

4.2.2 to 4.3+
=============

Module changes
--------------

* In case you wrote your own module which directly calls function
  ``kr_ranked_rrarray_add()``, you need to additionally call function
  ``kr_ranked_rrarray_finalize()`` after each batch (before changing
  the added memory regions). For a specific example see `changes in dns64 module
  <https://gitlab.labs.nic.cz/knot/knot-resolver/commit/edb8ffef7fbe48befeb3f7164d38079dd0be3302#1fe36e8ac0729b279645f7237b7122b1c457a982>`_.

.. _upgrade-from-3-to-4:

4.x to 4.2.1+
=============

Users
-----

* If you have previously installed ``knot-resolver-dbgsym`` package on Debian,
  please remove it and install ``knot-resolver-dbg`` instead.

3.x to 4.x
==========

Users
-----

* DNSSEC validation is now turned on by default. If you need to disable it, see
  :ref:`dnssec-config`.
* ``-k/--keyfile`` and ``-K/--keyfile-ro`` daemon options were removed. If needed,
  use ``trust_anchors.add_file()`` in configuration file instead.
* Configuration for :ref:`HTTP module <mod-http>` changed significantly as result of
  adding :ref:`mod-http-doh` support. Please see examples below.
* In case you are using your own custom modules, move them to the new module
  location. The exact location depends on your distribution. Generally, modules previously
  in ``/usr/lib/kdns_modules`` should be moved to ``/usr/lib/knot-resolver/kres_modules``.

Configuration file
~~~~~~~~~~~~~~~~~~

* ``trust_anchors.file``, ``trust_anchors.config()`` and ``trust_anchors.negative``
  aliases were removed to avoid duplicity and confusion. Migration table:

  .. csv-table::
     :header: "3.x configuration", "4.x configuration"

     "``trust_anchors.file = path``", "``trust_anchors.add_file(path)``"
     "``trust_anchors.config(path, readonly)``", "``trust_anchors.add_file(path, readonly)``"
     "``trust_anchors.negative = nta_set``", "``trust_anchors.set_insecure(nta_set)``"

* ``trust_anchors.keyfile_default`` is no longer accessible and is can be set
  only at compile time. To turn off DNSSEC, use :func:`trust_anchors.remove()`.

  .. csv-table::
     :header: "3.x configuration", "4.x configuration"

     "``trust_anchors.keyfile_default = nil``", "``trust_anchors.remove('.')``"

* Network for HTTP endpoints is now configured using same mechanism as for normal DNS enpoints,
  please refer to chapter :ref:`network-configuration`. Migration table:

  .. csv-table::
     :header: "3.x configuration", "4.x configuration"

     "``modules = { http = { host = '192.0.2.1', port = 443 }}``","see chapter :ref:`network-configuration`"
     "``http.config({ host = '192.0.2.1', port = 443 })``","see chapter :ref:`network-configuration`"
     "``modules = { http = { endpoints = ... }}``","see chapter :ref:`mod-http-custom-endpoint`"
     "``http.config({ endpoints = ... })``","see chapter :ref:`mod-http-custom-endpoint`"

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

* C modules defining ``*_layer`` or ``*_props`` symbols need to use a different style, but it's typically a trivial change.
  Instead of exporting the corresponding symbols, the module should assign pointers to its static structures inside its ``*_init()`` function.  Example migration:
  `bogus_log module <https://gitlab.labs.nic.cz/knot/knot-resolver/commit/2875a3970#9fa69cdc6ee1903dc22e3262f58996395acab364>`_.

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
