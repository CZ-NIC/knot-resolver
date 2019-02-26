
Cache configuration
^^^^^^^^^^^^^^^^^^^

The default cache in Knot Resolver is persistent with LMDB backend, this means that the daemon doesn't lose
the cached data on restart or crash to avoid cold-starts. The cache may be reused between cache
daemons or manipulated from other processes, making for example synchronized load-balanced recursors possible.

.. function:: cache.open(max_size[, config_uri])

   :param number max_size: Maximum cache size in bytes.
   :return: ``true`` if cache was opened

   Open cache with a size limit. The cache will be reopened if already open.
   Note that the max_size cannot be lowered, only increased due to how cache is implemented.

   .. tip:: Use ``kB, MB, GB`` constants as a multiplier, e.g. ``100*MB``.

   As of now, the built-in backend with URI ``lmdb://`` allows you to change the cache directory.

   Example:

   .. code-block:: lua

      cache.open(100 * MB, 'lmdb:///var/cache/knot-resolver')

.. envvar:: cache.size

   Set the cache maximum size in bytes. Note that this is only a hint to the backend,
   which may or may not respect it. See :func:`cache.open()`.

   .. code-block:: lua

	cache.size = 100 * MB -- equivalent to `cache.open(100 * MB)`

.. envvar:: cache.current_size

   Get the maximum size in bytes.

   .. code-block:: lua

	print(cache.current_size)

.. envvar:: cache.storage

   Set the cache storage backend configuration, see :func:`cache.backends()` for
   more information. If the new storage configuration is invalid, it is not set.

   .. code-block:: lua

	cache.storage = 'lmdb://.'

.. envvar:: cache.current_storage

   Get the storage backend configuration.

   .. code-block:: lua

	print(cache.storage)

.. function:: cache.backends()

   :return: map of backends

   The cache supports runtime-changeable backends, using the optional :rfc:`3986` URI, where the scheme
   represents backend protocol and the rest of the URI backend-specific configuration. By default, it
   is a ``lmdb`` backend in working directory, i.e. ``lmdb://``.

   Example output:

   .. code-block:: lua

   	[lmdb://] => true

.. function:: cache.count()

   :return: Number of entries in the cache. Meaning of the number is an implementation detail and is subject of change.

.. function:: cache.close()

   :return: ``true`` if cache was closed

   Close the cache.

   .. note:: This may or may not clear the cache, depending on the cache backend.

.. function:: cache.stats()

   Return table with low-level statistics for each internal cache operation.
   This counts each access to cache and does not directly map to individual
   DNS queries or resource records.
   For query-level statistics see :ref:`stats module <mod-stats>`.

   Example:

   .. code-block:: lua

       > cache.stats()
       [read_leq_miss] => 4
       [write] => 189
       [read_leq] => 9
       [read] => 4313
       [read_miss] => 1143
       [open] => 0
       [close] => 0
       [remove_miss] => 0
       [commit] => 117
       [match_miss] => 2
       [match] => 21
       [count] => 2
       [clear] => 0
       [remove] => 17

   Cache operation `read_leq` (*read less or equal*, i.e. range search) was requested 9 times,
   and 4 out of 9 operations were finished with *cache miss*.


.. function:: cache.max_ttl([ttl])

  :param number ttl: maximum cache TTL in seconds (default: 6 days)

  .. KR_CACHE_DEFAULT_TTL_MAX ^^

  :return: current maximum TTL

  Get or set maximum cache TTL.

  .. note:: The `ttl` value must be in range `(min_ttl, 4294967295)`.

  .. warning:: This settings applies only to currently open cache, it will not persist if the cache is closed or reopened.

  .. code-block:: lua

     -- Get maximum TTL
     cache.max_ttl()
     518400
     -- Set maximum TTL
     cache.max_ttl(172800)
     172800

.. function:: cache.min_ttl([ttl])

  :param number ttl: minimum cache TTL in seconds (default: 5 seconds)

  .. KR_CACHE_DEFAULT_TTL_MIN ^^

  :return: current maximum TTL

  Get or set minimum cache TTL. Any entry inserted into cache with TTL lower than minimal will be overridden to minimum TTL. Forcing TTL higher than specified violates DNS standards, use with care.

  .. note:: The `ttl` value must be in range `<0, max_ttl)`.

  .. warning:: This settings applies only to currently open cache, it will not persist if the cache is closed or reopened.

  .. code-block:: lua

     -- Get minimum TTL
     cache.min_ttl()
     0
     -- Set minimum TTL
     cache.min_ttl(5)
     5

.. function:: cache.ns_tout([timeout])

  :param number timeout: NS retry interval in milliseconds (default: :c:macro:`KR_NS_TIMEOUT_RETRY_INTERVAL`)
  :return: current timeout

  Get or set time interval for which a nameserver address will be ignored after determining that it doesn't return (useful) answers.
  The intention is to avoid waiting if there's little hope; instead, kresd can immediately SERVFAIL or immediately use stale records (with :ref:`serve_stale <mod-serve_stale>` module).

  .. warning:: This settings applies only to the current kresd process.

.. function:: cache.get([domain])

  This function is not implemented at this moment.
  We plan to re-introduce it soon, probably with a slightly different API.

.. function:: cache.clear([name], [exact_name], [rr_type], [chunk_size], [callback], [prev_state])

     Purge cache records matching specified criteria. There are two specifics:

     * To reliably remove **negative** cache entries you need to clear subtree with the whole zone. E.g. to clear negative cache entries for (formerly non-existing) record `www.example.com. A` you need to flush whole subtree starting at zone apex, e.g. `example.com.` [#]_.
     * This operation is asynchronous and might not be yet finished when call to ``cache.clear()`` function returns. Return value indicates if clearing continues asynchronously or not.

  :param string name: subtree to purge; if the name isn't provided, whole cache is purged
        (and any other parameters are disregarded).
  :param bool exact_name: if set to ``true``, only records with *the same* name are removed;
                          default: false.
  :param kres.type rr_type: you may additionally specify the type to remove,
        but that is only supported with ``exact_name == true``; default: nil.
  :param integer chunk_size: the number of records to remove in one round; default: 100.
        The purpose is not to block the resolver for long.
        The default ``callback`` repeats the command after one millisecond
        until all matching data are cleared.
  :param function callback: a custom code to handle result of the underlying C call.
        Its parameters are copies of those passed to `cache.clear()` with one additional
        parameter ``rettable`` containing table with return value from current call.
        ``count`` field contains a return code from :func:`kr_cache_remove_subtree()`.
  :param table prev_state: return value from previous run (can be used by callback)

  :rtype: table
  :return: ``count`` key is always present. Other keys are optional and their presence indicate special conditions.

   * **count** *(integer)* - number of items removed from cache by this call (can be 0 if no entry matched criteria)
   * **not_apex** - cleared subtree is not cached as zone apex; proofs of non-existence were probably not removed
   * **subtree** *(string)* - hint where zone apex lies (this is estimation from cache content and might not be accurate)
   * **chunk_limit** - more than ``chunk_size`` items needs to be cleared, clearing will continue asynchronously


  Examples:

  .. code-block:: lua

     -- Clear whole cache
     > cache.clear()
     [count] => 76

     -- Clear records at and below 'com.'
     > cache.clear('com.')
     [chunk_limit] => chunk size limit reached; the default callback will continue asynchronously
     [not_apex] => to clear proofs of non-existence call cache.clear('com.')
     [count] => 100
     [round] => 1
     [subtree] => com.
     > worker.sleep(0.1)
     [cache] asynchonous cache.clear('com', false) finished

     -- Clear only 'www.example.com.'
     > cache.clear('www.example.com.', true)
     [round] => 1
     [count] => 1
     [not_apex] => to clear proofs of non-existence call cache.clear('example.com.')
     [subtree] => example.com.

.. [#] This is a consequence of DNSSEC negative cache which relies on proofs of non-existence on various owner nodes. It is impossible to efficiently flush part of DNS zones signed with NSEC3.
