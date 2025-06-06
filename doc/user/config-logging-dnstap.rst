.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-logging-dnstap:

Dnstap (traffic collection)
===========================

The ``dnstap`` supports logging DNS requests and responses to a unix
socket in `dnstap format <https://dnstap.info>`_ using fstrm framing library.
This logging is useful if you need effectively log all DNS traffic.

The unix socket and the socket reader must be present before starting resolver instances.
Also it needs appropriate filesystem permissions;
the typical user and group for the resolver are called ``knot-resolver``.

Tunables:

* ``unix-socket``: the unix socket file where dnstap messages will be sent
* ``log-queries``: if ``true`` queries from downstream in wire format will be logged
* ``log-responses``: if ``true`` responses to downstream in wire format will be logged

.. Very non-standard and it seems unlikely that others want to collect the RTT.
.. * ``log-tcp-rtt``: if ``true`` and on Linux,
        add "extra" field with "rtt=12345\n",
        signifying kernel's current estimate of RTT micro-seconds for the non-UDP connection
        (alongside every arrived DNS message).

.. code-block:: yaml

    logging:
      dnstap:
        enable: true
        unix-socket: /tmp/dnstap.sock
        # by default log is disabled for all
        log-queries: true
        log-responses: true
