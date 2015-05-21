.. _mod-stats:

Statistics collector
--------------------

This modules gathers various counters from the query resolution and server internals,
and offers them as a key-value storage. Any module may update the metrics or simply hook
in new ones.

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

* ``answer.total``
* ``answer.cached``
* ``answer.unresolved``
* ``answer.noerror``
* ``answer.nxdomain``
* ``answer.servfail``
* ``query.concurrent``
* ``query.edns``
* ``query.dnssec``
* ``iterator.udp``
* ``iterator.tcp``
