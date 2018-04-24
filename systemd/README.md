Running Knot Resolver under systemd (or equivalent) socket activation
=====================================================================

You can use the files in this directory to run kresd under supervision
by systemd (or any supervisor that provides equivalent file descriptor
initialization via the interface supported by
sd_listen_fds_with_names(3)).

Usage and Configuration
-----------------------

See kresd.systemd(7) for details.

Compatibility with older systemd
--------------------------------

If you're using systemd prior to version 227, use the systemd-compat.conf
drop-in file to use manual activation. In this case, socket files shouldn't
be packaged, because they won't be used.

Notes
-----

*  If you're using the upstream systemd unit files, don't forget to also include
   doc/kresd.systemd.7 manual page in the package.
*  Distributions using systemd-sysv-generator should mask kresd.service to
   be consistent with other distributions. Any use of kresd.service instead of
   kresd@N.service is discouraged to avoid confusing the users.
