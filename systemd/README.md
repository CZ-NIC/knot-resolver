Running Knot Resolver under systemd (or equivalent) socket activation
=====================================================================

You can use the files in this directory to run kresd under supervision
by systemd (or any supervisor that provides equivalent file descriptor
initialization via the interface supported by
sd_listen_fds_with_names(3)).

Usage and Configuration
-----------------------

See kresd.systemd(7) for details.

Manual activation
-----------------

If you wish to use manual activation without sockets, you have to grant
the service the capability to bind to well-known ports. You can use a drop-in
file.

    # /etc/systemd/system/kresd@.service.d/override.conf
    [Service]
    AmbientCapabilities=CAP_NET_BIND_SERVICE

Notes
-----

*  If you're using systemd prior to version 227, use a drop-in file to change
   the service type to simple. See drop-in/systemd-compat.conf.

*  Distributors of systems using systemd may wish to place
   ./90-kresd.preset in /lib/systemd/systemd-preset/90-kresd.preset if
   they want to delay daemon launch until it is accessed. (see
   systemd.preset(5)).

*  Symlinks pointing from @1 to the systemd template are not necessary. They
   are only useful to provide users unfamiliar with kresd instances a hint
   when using bash completion.
