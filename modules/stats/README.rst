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

Built-in statistics
^^^^^^^^^^^^^^^^^^^

* ``answer.total`` - total number of answerered queries
* ``answer.cached`` - number of queries answered from cache
* ``answer.unresolved`` - number of unresolved queries (likely unresolvable path)
* ``answer.noerror`` - number of **NOERROR** answers
* ``answer.nxdomain`` - number of **NXDOMAIN** answers
* ``answer.servfail`` - number of **SERVFAIL** answers
* ``query.concurrent`` - number of concurrent queries at the moment
* ``query.edns`` - number of queries with EDNS
* ``query.dnssec`` - number of queries with DNSSEC DO=1
* ``iterator.udp`` - number of outbound queries over UDP
* ``iterator.tcp`` - number of outbound queries over TCP

  * Note that the iterator tracks **completed** queries over given protocol, total number of outbound requests must be tracked by the I/O layer.
