.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-edns_keepalive:

EDNS keepalive
==============

The ``edns_keepalive`` module implements :rfc:`7828` for *clients*
connecting to Knot Resolver via TCP and TLS.
The module just allows clients to discover the connection timeout,
client connections are always timed-out the same way *regardless*
of clients sending the EDNS option.

When connecting to servers, Knot Resolver does not send this EDNS option.
It still attempts to reuse established connections intelligently.

This module is loaded by default. For debugging purposes it can be
unloaded using standard means:

.. code-block:: lua

        modules.load('edns_keepalive')
