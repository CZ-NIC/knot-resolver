.. SPDX-License-Identifier: GPL-3.0-or-later

.. _upgrading:

*********
Upgrading
*********

This section summarizes steps required when upgrading to newer Knot Resolver versions.
We advise users to also read :ref:`release_notes` for respective versions.
Section *Module changes* is relevant only for users who develop or use third-party modules.


Upcoming changes
================

Following section provides information about selected changes in not-yet-released versions.
We advise users to prepare for these changes sooner rather than later to make it easier to upgrade to
newer versions when they are released.

* Command line option ``--forks`` (``-f``) `is deprecated and will be eventually removed
  <https://gitlab.nic.cz/knot/knot-resolver/-/issues/631>`_.
  Preferred way to manage :ref:`systemd-multiple-instances` is to use a process manager,
  e.g. systemd_ or supervisord_.
* Function :func:`verbose` is deprecated and will be eventually removed.
  Prefered way to change logging level is use to :func:`log_level`.

.. _`systemd`: https://systemd.io/
.. _`supervisord`: http://supervisord.org/


5.x to 6.0
==========

* `detailed upgrade guide <upgrading-to-6>`

5.4 to 5.5
==========

Packagers & Developers
----------------------

* Knot DNS >= 3.0.2 is required.

Module API changes
------------------
* Function `cache.zone_import` was removed;
  you can use `ffi.C.zi_zone_import` instead (different API).
* When using :ref:`proxyv2`, the meaning of ``qsource.flags`` and ``qsource.comm_flags``
  in :c:member:`kr_request` changes so that ``flags`` describes the original client
  communicating with the proxy, while ``comm_flags`` describes the proxy communicating
  with the resolver. When there is no proxy, ``flags`` and ``comm_flags`` are the same.


5.3 to 5.4
==========

Configuration file
------------------

* ``kind='doh'`` in :func:`net.listen` was renamed to ``kind='doh_legacy'``. It is recommended to switch to the new DoH implementation with ``kind='doh2'``.
* :func:`verbose` has been deprecated. In case you want to change logging level,
  there is new function :func:`log_level`.

Packagers & Developers
----------------------

* meson option ``verbose_log`` was removed.

Module changes
--------------

* lua function ``warn()`` was removed, use ``log_warn()`` instead. The new function takes a log group number as the first argument.
* C functions ``kr_log_req()`` and ``kr_log_q()`` were replaced by ``kr_log_req1()`` and ``kr_log_q1()`` respectively. The new function have slightly different API.


5.2 to 5.3
==========

Configuration file
------------------

* Module ``dnstap``: option ``log_responses`` has been moved inside a new ``client`` section. Refer to the configuration example in :ref:`mod-dnstap`.

Packagers & Developers
----------------------

* Knot DNS >= 2.9 is required.

5.1 to 5.2
==========

Users
-----

* DoH over HTTP/1 and unencrypted transports is still available in
  :ref:`legacy http module <mod-http-doh>` (``kind='doh'``).
  This module will not receive receive any more bugfixes and will be eventually removed.
* Users of :ref:`control-sockets` API need to terminate each command sent to resolver with newline
  character (ASCII ``\n``). Correct usage: ``cache.stats()\n``.
  Newline terminated commands are accepted by all resolver versions >= 1.0.0.
* `DNS Flag Day 2020 <https://dnsflagday.net/2020/>`_ is now effective and Knot Resolver uses
  maximum size of UDP answer to 1232 bytes. Please double-check your firewall,
  it has to allow DNS traffic on UDP and **also TCP** port 53.
* Human readable output in interactive mode and from :ref:`control-sockets` was improved and
  as consequence slightly changed its format. Users who need machine readable output for scripts
  should use Lua function ``tojson()`` to convert Lua values into standard JSON format instead
  of attempting to parse the human readable output.
  For example API call ``tojson(cache.stats())\n`` will return JSON string with ``cache.stats()``
  results represented as dictionary.
  Function ``tojson()`` is available in all resolver versions >= 1.0.0.

Configuration file
------------------

* Statistics exporter :ref:`mod-graphite` now uses default prefix which combines
  :func:`hostname()` and :envvar:`worker.id` instead of bare :func:`hostname()`.
  This prevents :ref:`systemd-multiple-instances` from sending
  conflicting statistics to server. In case you want to continue in previous time series you
  can manually set the old values using option ``prefix``
  in :ref:`Graphite configuration <mod-graphite>`.
  Beware that non-default values require careful
  :ref:`instance-specific-configuration` to avoid conflicting names.
* Lua variable :envvar:`worker.id` is now a string with either Systemd instance name or PID
  (instead of number). If your custom configuration uses :envvar:`worker.id` value please
  check your scripts.

Module changes
--------------
* Reply packet :c:type:`kr_request.answer`
  `is not allocated <https://gitlab.nic.cz/knot/knot-resolver/-/merge_requests/985>`_
  immediately when the request comes.
  See the new :c:func:`kr_request_ensure_answer` function,
  wrapped for lua as ``req:ensure_answer()``.


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

* Network for HTTP endpoints is now configured using same mechanism as for normal DNS endpoints,
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
