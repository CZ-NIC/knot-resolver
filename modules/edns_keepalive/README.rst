.. _mod-edns_keepalive:

EDNS keepalive
--------------

The ``edns_keepalive`` module implements :rfc:`7828` for *clients* connecting to Knot Resolver via TCP and TLS.
Note that client connections are timed-out the same way *regardless* of them sending the EDNS option;
the module just allows clients to discover the timeout.

When connecting to servers, Knot Resolver does not send this EDNS option.
It still attempts to reuse established connections intelligently.

