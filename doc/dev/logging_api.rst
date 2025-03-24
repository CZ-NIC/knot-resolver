.. SPDX-License-Identifier: GPL-3.0-or-later

Logging API reference
=====================

Logging overview
----------------

Kresd process uses one of several logging targets according to its configuration;
it can log to ``stdout``, ``stderr`` and ``syslog`` (either via ``syslog`` function of via ``libsystemd``).
There is also rarely used async-signal-safe way of logging defined in ``lib/sigsafe.h``,
which tries to be as consistent with the standard logging as possible,
though some inconsistencies arise to avoid unsafe function calls like ``syslog``.

Based on how knot-resolver was executed, there are different ways of handling logs:

With systemd service using manager (the standard way)
each process (incl. manager, etc) uses ``syslog``/``libsystemd`` directly,
sigsafe variant prints lines prefixed with loglevel to ``stderr``,
which should be handled by systemd the same way.
Using systemd without manager (the legacy way) works the same.

When using manager with non-systemd syslog,
all processes use directly ``syslog``,
sigsafe uses the ``stderr`` with prefixing as before,
which is now handled by supervisor resending the output using ``syslog``.
The form of the messages may be a little different, but all end up in the syslog.
As supervisor cannot handle syslog loglevels by itself,
all sigsafe messages use the same level in this case.

When using manager with stdout logging (``./poe run``),
each process prints to stdout,
which is prefixed with timestamp and process name by supervisor.
Sigsafe works the same (no loglevel prefixing).

When spawning kresd on your own, logging target depends on your configuration.
If logging to ``stdout``/``stderr``, sigsafe is consistent;
if using ``syslog``, you need to handle also ``<N>``-prefixed lines on ``stderr``.


API reference
-------------

.. _config_log_groups:

.. doxygenfile:: lib/log.h
    :project: libkres
