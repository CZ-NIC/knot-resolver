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

If you wish to use manual activation without sockets, you have to
grant the service the capability to bind to well-known ports, and you
should disable allocation of other sockets from systemd itself. You
can use a drop-in file like so:

    # /etc/systemd/system/kresd@.service.d/override.conf
    [Service]
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    Sockets=

If you do this, make sure you've indicated which ports to bind to in
/etc/knot-resolver/kresd.conf , and also do:

    systemctl disable --now kresd.socket kresd-tls.socket 'kresd-control@*.socket'

Notes
-----

*  If you're using systemd prior to version 227, use a drop-in file to change
   the service type to simple. See drop-in/systemd-compat.conf.
