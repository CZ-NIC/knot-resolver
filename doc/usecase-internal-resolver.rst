.. SPDX-License-Identifier: GPL-3.0-or-later

.. _usecase-internal-resolver:

*****************
Internal Resolver
*****************

When running the resolver for the local network, not much has to be changed and the configuration looks essentially the same as when running locally.

.. code-block:: yaml

    rundir: /var/run/knot-resolver
    workers: auto  # run as many worker processes as there are available CPU cores
    management:
        unix-socket: /var/run/knot-resolver/manager.sock
    cache:
        storage: /var/cache/knot-resolver
        size-max: 100MB
    network:
        listen:
          - interface: 'eth0'
            port: 53
            kind: 'dns'
