.. _mod-zone_forward:

Zone forwarding
---------------

Prototype.

This is a module to provide zone forwarding to an authoritative server. In
comparison to policy module's FORWARD, this modules enables forwarding even
when following CNAMEs and respects delegations present within the forwarded
zone.

Examples
^^^^^^^^

.. code-block:: lua

    -- Zone forwards need to be processed first
    modules = { 'zone_forward < iterate' }

    -- Configure forwarding
    zone_forward.config { zone="example.com.", ip="192.0.2.42" }
