Redis cache storage
-------------------

This modules provides Redis_ backend for cache storage. Redis is a BSD-license key-value cache and storage server.
Like memcached_ backend, Redis provides master-server replication, but also weak-consistency clustering.

After loading you can see the storage backend registered and useable.

.. code-block:: lua

	> modules.load 'redis'
	> cache.backends()
	[redis://] => true

Redis client support TCP or UNIX sockets.

.. code-block:: lua

	> cache.storage = 'redis://127.0.0.1'
	> cache.storage = 'redis://127.0.0.1:6398'
	> cache.storage = 'redis:///tmp/redis.sock'

It also supports indexed databases if you prefix the configuration string with ``DBID@``.

.. code-block:: lua

	> cache.storage = 'redis://9@127.0.0.1'

.. warning:: The Redis client doesn't really support transactions nor pruning. Cache eviction policy shoud be left upon Redis server, see the `Using Redis as an LRU cache <redis-lru_>`_.

Build distributed cache
^^^^^^^^^^^^^^^^^^^^^^^

See `Redis Cluster`_ tutorial.

Dependencies
^^^^^^^^^^^^

Depends on the hiredis_ library, which is usually in the packages / ports or you can install it from sources.

.. _Redis: http://redis.io/
.. _memcached: https://memcached.org/
.. _`Redis Cluster`: http://redis.io/topics/cluster-tutorial
.. _hiredis: https://github.com/redis/hiredis
.. _redis-lru: http://redis.io/topics/lru-cache
