Memcached cache storage
-----------------------

Module providing a cache storage backend for memcached_, which makes a good fit for
making a shared cache between resolvers.

After loading you can see the storage backend registered and useable.

.. code-block:: lua

	> modules.load 'kmemcached'
	> cache.backends()
	[memcached://] => true

And you can use it right away, see the `libmemcached configuration`_ reference for configuration string
options, the most essential ones are `--SERVER` or `--SOCKET`. Here's an example for connecting to UNIX socket.

.. code-block:: lua

	> cache.storage = 'memcached://--SOCKET="/var/sock/memcached"'

.. note:: The memcached_ instance **MUST** support binary protocol, in order to make it work with binary keys. You can pass other options to the configuration string for performance tuning.

.. warning:: The memcached_ server is responsible for evicting entries out of cache, the pruning function is not implemented, and neither is aborting write transactions.

Build resolver shared cache
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The memcached_ takes care of the data replication and fail over, you can add multiple servers at once.

.. code-block:: lua

	> cache.storage = 'memcached://--SOCKET="/var/sock/memcached" --SERVER=192.168.1.1 --SERVER=cache2.domain'

Dependencies
^^^^^^^^^^^^

Depends on the libmemcached_ library.

.. _memcached: https://memcached.org/
.. _libmemcached: http://libmemcached.org/libMemcached.html
.. _`libmemcached configuration`: http://docs.libmemcached.org/libmemcached_configuration.html#description
