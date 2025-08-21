.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-serve-stale:

Fallback on resolution failure
==============================

This allows switching to a fallback forwarding configuration on queries where the resolver is unable to contact upstream servers.

.. code-block:: yaml

        fallback:
          enable: true
          servers:
            - address: [ 2001:148f:fffe::1, 193.17.47.1 ]
              transport: tls
              hostname: odvr.nic.cz

The ``servers:`` has the same schema as in :ref:`forwarding <config-forward>`.

If you use fallback within a fleet of servers,
you will probably want to avoid queries cycling in there,
i.e. disable the fallback option for them in :ref:`views <config-views>`.
