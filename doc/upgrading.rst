.. SPDX-License-Identifier: GPL-3.0-or-later

.. _upgrading:

*********
Upgrading
*********

This section summarizes steps required when upgrading to newer Knot Resolver versions.
We advise users to also read :ref:`release_notes` for respective versions.
Section *Module changes* is relevant only for users who develop or use third-party modules.

Version numbering
=================
Version number format is ``major.minor.patch``.
Leftmost number which was changed signalizes what to expect when upgrading:

Major version
    * Manual upgrade steps might be necessary, please follow instructions in Upgrading guide (this document).
    * Major releases contain significant changes including changes to configuration format.
    * We might release new major also when internal implementation details were changed significantly. *May contain nuts.*

Minor version
   * Configuration stays compatible with the previous version, except for undocumented or very obscure options.
   * Users who use modules shipped as part of Knot Resolver distribution are expected to upgrade without manual steps.
   * Incompatible changes in internal APIs are allowed in minor versions, i.e. users who develop or use custom modules
     (i.e. modules not distributed together with Knot Resolver) need to double check their own code for incompatibilities.
     Upgrading guide should contain hints for module authors.

Patch version
    * Everything should be compatible including API for modules.
    * Custom modules might need to be recompiled, i.e. ABI compatibility is not guaranteed.


Upcoming changes
================

Following section provides information about selected changes in not-yet-released versions.
We advise users to prepare for these changes sooner rather than later to make it easier to upgrade to
newer versions when they are released.

* Users of :ref:`control-sockets` API need to terminate each command sent to resolver with newline
  character (ASCII ``\n``). Correct usage: ``cache.stats()\n``.
  Newline terminated commands are accepted by all resolver versions >= 1.0.0.
* Human readable output from :ref:`control-sockets` is not stable and changes from time to time.
  Users who need machine readable output for scripts should use Lua function
  ``tojson()`` to convert Lua values into standard JSON format instead of attempting to parse
  the human readable output. For example API call ``tojson(cache.stats())\n`` will return JSON string
  with ``cache.stats()`` results represented as dictionary.
  Function ``tojson()`` is available in all resolver versions >= 1.0.0.
* DoH served with http module :ref:`DNS-over-HTTP (DoH) <mod-http-doh>` will be marked as legacy
  and won't receive any more bugfixes. A more reliable and scalable DoH module will be available
  instead. The new DoH module will only support HTTP/2 over TLS.
* New releases since Octomer 2020 will contain changes for
  `DNS Flag Day 2020 <https://dnsflagday.net/2020/>`_. Please double-check your firewall,
  it has to allow DNS traffic on UDP and also TCP port 53.

5.0 to 5.1
==========

Module changes
--------------

* Modules which use :c:type:`kr_request.trace_log` handler need update to modified handler API. Example migration is `modules/watchdog/watchdog.lua <https://gitlab.nic.cz/knot/knot-resolver/-/merge_requests/957/diffs#6831501329bbf9e494048fe269c6b02944fc227c>`_.
* Modules which were using logger :c:func:`kr_log_qverbose_impl` need migration to new logger :c:func:`kr_log_q`. Example migration is `modules/rebinding/rebinding.lua <https://gitlab.nic.cz/knot/knot-resolver/-/merge_requests/957/diffs#6c74dcae147221ca64286a3ed028057adb6813b9>`_.
* Modules which were using :c:func:`kr_ranked_rrarray_add` should note that on success it no longer returns exclusively zero but index into the array (non-negative).  Error states are unchanged (negative).


4.x to 5.x
==========

Users
-----

* Control socket location has changed

  .. csv-table::
     :header: "","4.x location","5.x location"

     "with systemd","``/run/knot-resolver/control@$ID``","``/run/knot-resolver/control/$ID``"
     "without systemd","``$PWD/tty/$PID``","``$PWD/control/$PID``"

* ``-f`` / ``--forks`` command-line option is deprecated.
  In case you just want to trigger non-interactive mode, there's new ``-n`` / ``--noninteractive``.
  This forking style `was not ergonomic <https://gitlab.nic.cz/knot/knot-resolver/issues/529>`_;
  with independent kresd processes you can better utilize a process manager (e.g. systemd).


Configuration file
------------------

* Network interface are now configured in ``kresd.conf`` with
  :func:`net.listen` instead of systemd sockets (`#485
  <https://gitlab.nic.cz/knot/knot-resolver/issues/485>`_). See
  the following examples.

  .. tip:: You can find suggested network interface settings based on your
     previous systemd socket configuration in
     ``/var/lib/knot-resolver/.upgrade-4-to-5/kresd.conf.net`` which is created
     during the package update to version 5.x.

  .. csv-table::
     :header: "4.x - systemd socket file", "5.x - kresd.conf"

      "kresd.socket
      | [Socket]
      | ListenDatagram=127.0.0.1:53
      | ListenStream=127.0.0.1:53","| ``net.listen('127.0.0.1', 53, { kind = 'dns' })``"
      "kresd.socket
      | [Socket]
      | FreeBind=true
      | BindIPv6Only=both
      | ListenDatagram=[::1]:53
      | ListenStream=[::1]:53
      "," | ``net.listen('127.0.0.1', 53, { kind = 'dns', freebind = true })``
      | ``net.listen('::1', 53, { kind = 'dns', freebind = true })``"
      "kresd-tls.socket
      | [Socket]
      | ListenStream=127.0.0.1:853","| ``net.listen('127.0.0.1', 853, { kind = 'tls' })``"
      "kresd-doh.socket
      | [Socket]
      | ListenStream=127.0.0.1:443","| ``net.listen('127.0.0.1', 443, { kind = 'doh' })``"
      "kresd-webmgmt.socket
      | [Socket]
      | ListenStream=127.0.0.1:8453","| ``net.listen('127.0.0.1', 8453, { kind = 'webmgmt' })``"

* :func:`net.listen` throws an error if it fails to bind. Use ``freebind=true`` option
  to bind to nonlocal addresses.


4.2.2 to 4.3+
=============

Module changes
--------------

* In case you wrote your own module which directly calls function
  ``kr_ranked_rrarray_add()``, you need to additionally call function
  ``kr_ranked_rrarray_finalize()`` after each batch (before changing
  the added memory regions). For a specific example see `changes in dns64 module
  <https://gitlab.nic.cz/knot/knot-resolver/commit/edb8ffef7fbe48befeb3f7164d38079dd0be3302#1fe36e8ac0729b279645f7237b7122b1c457a982>`_.

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
  `bogus_log module <https://gitlab.nic.cz/knot/knot-resolver/commit/2875a3970#9fa69cdc6ee1903dc22e3262f58996395acab364>`_.

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
