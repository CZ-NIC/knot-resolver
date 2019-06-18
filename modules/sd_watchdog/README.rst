.. _mod-bogus_log:

Systemd watchdog
----------------

This module is always loaded by default. It enables the use systemd watchdog to
restart the process in case it stops responding.  The upstream systemd unit
files are configured to use this feature, which is turned on with the
``WatchdogSec=`` directive in the service file.
