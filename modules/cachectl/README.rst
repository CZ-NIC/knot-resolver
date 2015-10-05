Cache control
-------------

Module providing an interface to cache database, for inspection, manipulation and purging.

Example
^^^^^^^

.. code-block:: lua

	-- Query cache for 'domain.cz'
	cachectl['domain.cz']
	-- Query cache for all records at/below 'insecure.net'
	cachectl['*.insecure.net']
	-- Clear 'bad.cz' records
	cachectl.clear('bad.cz')
	-- Clear records at/below 'bad.cz'
	cachectl.clear('*.bad.cz')
	-- Clear packet cache
	cachectl.clear('*. P')
	-- Clear whole cache
	cachectl.clear()

Properties
^^^^^^^^^^

.. function:: cachectl.prune([max_count])

  :param number max_count:  maximum number of items to be pruned at once (default: 65536)
  :return: ``{ pruned: int }``

  Prune expired/invalid records.

.. function:: cachectl.get([domain])

  :return: list of matching records in cache

  Fetches matching records from cache. The **domain** can either be:

  - a domain name (e.g. ``"domain.cz"``)
  - a wildcard (e.g. ``"*.domain.cz"``)

  The domain name fetches all records matching this name, while the wildcard matches all records at or below that name.

  You can also use a special namespace ``"P"`` to purge NODATA/NXDOMAIN matching this name (e.g. ``"domain.cz P"``).

  .. note:: This is equivalent to ``cachectl['domain']`` getter.

.. function:: cachectl.clear([domain])

  :return: ``bool``

  Purge cache records. If the domain isn't provided, whole cache is purged. See *cachectl.get()* documentation for subtree matching policy.
