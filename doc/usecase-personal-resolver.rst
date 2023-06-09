.. SPDX-License-Identifier: GPL-3.0-or-later

.. _usecase-personal-resolver:

*****************
Personal Resolver
*****************

For local usage on a single system, configuration like the following should be sufficient. Equivalent configuration is the default and should be packaged by your distribution of choice.

.. code-block:: yaml

    rundir: /var/run/knot-resolver
    workers: 1
    management:
        unix-socket: /var/run/knot-resolver/manager.sock
    cache:
        storage: /var/cache/knot-resolver
        size-max: 10MB
    network:
        listen:
            - interface: 127.0.0.1@53