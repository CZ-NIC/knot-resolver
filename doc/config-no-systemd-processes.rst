.. SPDX-License-Identifier: GPL-3.0-or-later

Process management
==================

There following should be taken into consideration when running without systemd:

* To utilize multiple CPUs, kresd has to be executed as several independent
  processes.
* Maintenance daemon(s) have to be executed separately.
* If a process crashes, it might be useful to restart it.
* Using some mechanism similar to :ref:`mod-watchdog` might be desirable to
  recover in case a process becomes unresponsive.

Please note, systemd isn't the only process manager and other solutions exist,
such as supervisord_. Configuring these is out of the scope of this
document. Please refer to their respective documentations.

It is also possible to use kresd without any process management at all, which
may be suitable for some purposes (such as low-traffic local / home network resolver,
testing, development or debugging).

.. include:: ../utils/cache_gc/README.rst

.. _`supervisord`: http://supervisord.org/
