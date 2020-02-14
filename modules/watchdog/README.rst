.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-watchdog:

Watchdog
========

This module cooperates with Systemd watchdog to restart the process in case
the internal event loop gets stuck. The upstream Systemd unit files are configured
to use this feature, which is turned on with the ``WatchdogSec=`` directive
in the service file.

As an optional feature, this module can also do an internal DNS query to check if resolver
answers correctly. To use this feature you must configure DNS name and type to query for:

.. code-block:: lua

	watchdog.config({ qname = 'nic.cz.', qtype = kres.type.A })

Each single query from watchdog must result in answer with
RCODE = NOERROR or NXDOMAIN. Any other result will terminate the resolver
(with SIGABRT) to allow the supervisor process to do cleanup, gather coredump
and restart the resolver.

It is recommended to use a name with a very short TTL to make sure the watchdog
is testing all parts of resolver and not only its cache. Obviously this check
makes sense only when used with very reliable domains; otherwise a failure
on authoritative side will shutdown resolver!

`WatchdogSec` specifies deadline for supervisor when the process will be killed.
Watchdog queries are executed each `WatchdogSec / 2` seconds.
This implies that **half** of `WatchdogSec` interval must be long enough for
normal DNS query to succeed, so do not forget to add two or three seconds
for random network timeouts etc.

The module is loaded by default. If you'd like to disable it you can unload it:

.. code-block:: lua

   modules.unload('watchdog')

Beware that unloading the module without disabling watchdog feature in supervisor
will lead to infinite restart loop.
