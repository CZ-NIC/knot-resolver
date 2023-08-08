.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-edns-keepalive:

EDNS keepalive
==============

Implementation of :rfc:`7828` for *clients*
connecting to Knot Resolver via TCP and TLS.
It just allows clients to discover the connection timeout,
client connections are always timed-out the same way *regardless*
of clients sending the EDNS option.

When connecting to servers, Knot Resolver does not send this EDNS option.
It still attempts to reuse established connections intelligently.

It is enabled by default. For debugging purposes it can be
disabled in configuration file.

.. code-block:: yaml

   options:
     edns-tcp-keepalive: false
