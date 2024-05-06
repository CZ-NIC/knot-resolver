.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-cache:

Cache
=====

Cache in Knot Resolver is shared between :ref:`multiple workers <config-multiple-workers>`
and stored in a file, so resolver doesn't lose the cached data on restart or crash.

To improve performance even further the resolver implements so-called aggressive caching
for DNSSEC-validated data (:rfc:`8198`), which improves performance and also protects
against some types of Random Subdomain Attacks.


.. _config-cache-sizing:

Sizing
------

For personal and small office use-cases cache size around 100 MB is more than enough.

For large deployments we recommend to run Knot Resolver on a dedicated machine,
and to allocate 90% of machine's free memory for resolver's cache.

.. note::

   Choosing a cache size that can fit into RAM is important even if the
   cache is stored on disk (default). Otherwise, the extra I/O caused by disk
   access for missing pages can cause performance issues.

For example, imagine you have a machine with 16 GB of memory.
After machine restart you use command ``free -m`` to determine
amount of free memory (without swap):

.. code-block:: bash

  $ free -m
                total        used        free
  Mem:          15907         979       14928

Now you can configure cache size to be 90% of the free memory 14 928 MB, i.e. 13 453 MB:

.. code-block:: yaml

   -- 90 % of free memory after machine restart
   cache:
     size-max: 13453M


.. _config-cache-clear:

Clearing
--------

You can use :ref:`kresctl <manager-client-commands>` to clear (parts of) the cache, e.g.:

.. code-block:: none

   $ kresctl cache clear example.com.

   $ kresctl cache clear --help

It is also possible to use HTTP API directly: :ref:`manager-api-cache-clear`.

There are two specifics to purging cache records matching specified criteria:

* To reliably remove negative cache entries, you need to clear the subtree with the whole zone. E.g. to clear negative cache entries for the (formerly non-existent)
  record ``www.example.com. A``, you need to flush the whole subtree starting at the zone apex `example.com.` or closer to the root. [#]_
* This operation is asynchronous and might not yet be finished when the call to the ``/cache/clear`` API endpoint returns.
  The return value indicates if clearing continues asynchronously or not.

.. [#] This is a consequence of DNSSEC negative cache which relies on proofs of non-existence on various owner nodes. It is impossible to efficiently flush part of DNS zones signed with NSEC3.


.. _config-cache-persistence:

Persistence
-----------

.. tip:: Using ``tmpfs`` for cache improves performance and reduces disk I/O.

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

.. note::

   In most of the Unix-like systems ``/tmp`` and ``/var/run`` are
   commonly mounted as tmpfs.  While it is technically possible to move the
   cache to an existing tmpfs filesystem, it is *not recommended*, since the
   path to cache is configured in multiple places.

Mounting the cache directory as tmpfs_ is the recommended approach.  Make sure
to use appropriate ``size-max`` option and don't forget to adjust the size in the
config file as well.

.. code-block:: none

   # /etc/fstab
   tmpfs	/var/cache/knot-resolver	tmpfs	rw,size=2G,uid=knot-resolver,gid=knot-resolver,nosuid,nodev,noexec,mode=0700 0 0

.. code-block:: yaml

   # /etc/knot-resolver/config.yaml
   cache:
     storage: /var/cache/knot-resolver
     size-max: 1G

.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs


Configuration reference
-----------------------

.. option:: cache/storage: <dir>

   :default: /var/cache/knot-resolver

.. option:: cache/size-max: <size B|K|M|G>

   :default: 100M

.. note:: Use ``B, K, M, G`` bytes units prefixes.

Opens cache with a size limit. The cache will be reopened if already open.
Note that the maximum size cannot be lowered, only increased due to how cache is implemented.

.. code-block:: yaml

   cache:
      storage: /var/cache/knot-resolver
      size-max: 400M

.. option:: cache/ttl-max: <time ms|s|m|h|d>

   :default: 1d

   Higher TTL bound applied to all received records.

.. option:: cache/ttl-min: <time ms|s|m|h|d>

   :default: 5s

   Lower TTL bound applied to all received records.
   Forcing TTL higher than specified violates DNS standards, so use higher values with care.
   TTL still won't be extended beyond expiration of the corresponding DNSSEC signature.

.. code-block:: yaml

   cache:
      # max TTL must be always higher than min
      ttl-max: 2d
      ttl-min: 20s

.. option:: cache/ns-timeout: <time ms|s|m|h|d>

   :default: 1000ms

   Time interval for which a nameserver address will be ignored after determining that it doesn't return (useful) answers.
   The intention is to avoid waiting if there's little hope; instead, kresd can immediately SERVFAIL or immediately use stale records (with :ref:`serve-stale <config-serve-stale>`).
