.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-dnstap:

Dnstap (traffic collection)
===========================

The ``dnstap`` module supports logging DNS requests and responses to a unix
socket in `dnstap format <https://dnstap.info>`_ using fstrm framing library.
This logging is useful if you need effectivelly log all DNS traffic.

The unix socket and the socket reader must be present before starting resolver instances.

Tunables:

* ``socket_path``: the the unix socket file where dnstap messages will be sent
* ``identity``: identity string as typically returned by an "NSID" (RFC 5001) query, empty by default
* ``version``: version string of the resolver, defaulting to "Knot Resolver major.minor.patch"
* ``client.log_requests``: if ``true`` requests from downstream in wire format will be logged
* ``client.log_responses``: if ``true`` responses to downstream in wire format will be logged

.. code-block:: lua

    modules = {
        dnstap = {
            socket_path = "/tmp/dnstap.sock",
            identity = nsid.name() or "",
            version = "My Custom Knot Resolver " .. package_version(),
            client = {
                log_requests = true,
                log_responses = true,
            },
        }
    }
