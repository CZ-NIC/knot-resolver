.. _mod-stats:

Statistics collector
--------------------

This modules gathers various counters from the query resolution and server internals,
and offers them as a key-value storage. Any module may update the metrics or simply hook
in new ones.

.. code-block:: lua

	-- Enumerate metrics
	> stats.list()
	[answer.cached] => 486178
	[iterator.tcp] => 490
	[answer.noerror] => 507367
	[answer.total] => 618631
	[iterator.udp] => 102408
	[query.concurrent] => 149

	-- Query metrics by prefix
	> stats.list('iter')
	[iterator.udp] => 105104
	[iterator.tcp] => 490

	-- Set custom metrics from modules
	> stats['filter.match'] = 5
	> stats['filter.match']
	5

	-- Fetch most common queries
	> stats.frequent()
	[1] => {
		[type] => 2
		[count] => 4
		[name] => cz.
	}

	-- Fetch most common queries (sorted by frequency)
	> table.sort(stats.frequent(), function (a, b) return a.count > b.count end)

Properties
^^^^^^^^^^

.. function:: stats.get(key)

  :param string key: i.e. ``"answer.total"``
  :return: ``number``

Return nominal value of given metric. 

.. function:: stats.set(key, val)

  :param string key:  i.e. ``"answer.total"``
  :param number val:  i.e. ``5``

Set nominal value of given metric.

.. function:: stats.list([prefix])

  :param string prefix:  optional metric prefix, i.e. ``"answer"`` shows only metrics beginning with "answer"

Outputs collected metrics as a JSON dictionary.

.. function:: stats.frequent()

Outputs list of most frequent iterative queries as a JSON array. The queries are sampled probabilistically,
and include subrequests. The list maximum size is 5000 entries, make diffs if you want to track it over time.

.. function:: stats.clear_frequent()

Clear the list of most frequent iterative queries.

.. function:: stats.expiring()

Outputs list of soon-to-expire records as a JSON array.
The list maximum size is 5000 entries, make diffs if you want to track it over time.

.. function:: stats.clear_expiring()

Clear the list of soon expiring records.

Built-in statistics
^^^^^^^^^^^^^^^^^^^

* ``answer.total`` - total number of answered queries
* ``answer.cached`` - number of queries answered from cache
* ``answer.noerror`` - number of **NOERROR** answers
* ``answer.nodata`` - number of **NOERROR**, but empty answers
* ``answer.nxdomain`` - number of **NXDOMAIN** answers
* ``answer.servfail`` - number of **SERVFAIL** answers
* ``answer.10ms`` - number of answers completed in 10ms
* ``answer.100ms`` - number of answers completed in 100ms
* ``answer.1000ms`` - number of answers completed in 1000ms
* ``answer.slow`` - number of answers that took more than 1000ms
* ``query.edns`` - number of queries with EDNS
* ``query.dnssec`` - number of queries with DNSSEC DO=1
