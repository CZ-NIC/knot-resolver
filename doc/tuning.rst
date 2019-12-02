.. _tuning:

************************
Performance Tuning Guide
************************

The out-of-the box configuration of the upstream Knot Resolver packages is
intended for personal or small-scale use. Any deployments with traffic over 100
queries per second will likely benefit from the recommendations in this guide.


Utilizing multiple CPUs
=======================

The server can run in multiple independent processes, all sharing the same socket and cache. These processes can be started or stopped during runtime based on the load.

**Using systemd**

To run multiple daemons using systemd, use a different numeric identifier for
the instance, for example:

.. code-block:: bash

   $ systemctl start kresd@1.service
   $ systemctl start kresd@2.service
   $ systemctl start kresd@3.service
   $ systemctl start kresd@4.service

With the use of brace expansion, the equivalent command looks like:

.. code-block:: bash

   $ systemctl start kresd@{1..4}.service

For more details, see ``kresd.systemd(7)``.

**Daemon only**

.. code-block:: bash

   $ kresd -f 4 rundir > kresd.log &
   $ kresd -f 2 rundir > kresd_2.log & # Extra instances
   $ pstree $$ -g
   bash(3533)─┬─kresd(19212)─┬─kresd(19212)
              │              ├─kresd(19212)
              │              └─kresd(19212)
              ├─kresd(19399)───kresd(19399)
              └─pstree(19411)
   $ kill 19399 # Kill group 2, former will continue to run
   bash(3533)─┬─kresd(19212)─┬─kresd(19212)
              │              ├─kresd(19212)
              │              └─kresd(19212)
              └─pstree(19460)

.. _daemon-reuseport:

.. note:: On recent Linux supporting ``SO_REUSEPORT`` (since 3.9, backported to RHEL 2.6.32) it is also able to bind to the same endpoint and distribute the load between the forked processes. If your OS doesn't support it, use only one daemon process.

