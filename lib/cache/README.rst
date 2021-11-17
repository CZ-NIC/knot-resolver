.. SPDX-License-Identifier: GPL-3.0-or-later

.. _cache_sizing:

Cache sizing
------------

For personal use-cases and small deployments cache size around 100 MB is more than enough.

For large deployments we recommend to run Knot Resolver on a dedicated machine, and to allocate 90% of machine's free memory for resolver's cache.

For example, imagine you have a machine with 16 GB of memory.
After machine restart you use command ``free -m`` to determine amount of free memory (without swap):

.. code-block:: bash

  $ free -m
                total        used        free
  Mem:          15907         979       14928

Now you can configure cache size to be 90% of the free memory 14 928 MB, i.e. 13 453 MB:

.. code-block:: lua

   -- 90 % of free memory after machine restart
   cache.size = 13453 * MB

.. _cache_persistence:

Cache persistence
-----------------
.. tip:: Using tmpfs for cache improves performance and reduces disk I/O.

By default the cache is saved on a persistent storage device
so the content of the cache is persisted during system reboot.
This usually leads to smaller latency after restart etc.,
however in certain situations a non-persistent cache storage might be preferred, e.g.:

  - Resolver handles high volume of queries and I/O performance to disk is too low.
  - Threat model includes attacker getting access to disk content in power-off state.
  - Disk has limited number of writes (e.g. flash memory in routers).

If non-persistent cache is desired configure cache directory to be on
tmpfs_ filesystem, a temporary in-memory file storage.
The cache content will be saved in memory, and thus have faster access
and will be lost on power-off or reboot.


.. note:: In most of the Unix-like systems ``/tmp`` and ``/var/run`` are commonly mounted to tmpfs.
   While it is technically possible to move the cache to an existing
   tmpfs filesystem, it is *not recommended*: The path to cache is specified in
   multiple systemd units, and a shared tmpfs space could be used up by other
   applications, leading to ``SIGBUS`` errors during runtime.

Mounting the cache directory as tmpfs_ is recommended approach.
Make sure to use appropriate ``size=`` option and don't forget to adjust the
size in the config file as well.

.. code-block::

   # /etc/fstab
   tmpfs	/var/cache/knot-resolver	tmpfs	rw,size=2G,uid=knot-resolver,gid=knot-resolver,nosuid,nodev,noexec,mode=0700 0 0

.. code-block:: lua

   # /etc/knot-resolver/config
   cache.size = 2 * GB

.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs
