.. _mod-dnstap:

Dnstap
------

Dnstap module currently supports logging dns responses to a unix socket
in dnstap format using fstrm framing library.  The unix socket and the
socket reader should be present before starting kresd.

Configuration
^^^^^^^^^^^^^
Tunables:

* ``sockpath``: the the unix socket file where dnstap messages will be sent
* ``logRespPkt``: if true responses in wire format will be logged

.. code-block:: lua

    modules = {
        dnstap = {
            sockPath = "/tmp/dnstap.sock",
            logRespPkt = true
        }
    }
