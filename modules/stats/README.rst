.. _mod-stats:

Statistics collector
--------------------

This modules gathers various counters from the query resolution and server internals,
and offers them as a key-value storage.

Properties
^^^^^^^^^^

.. function:: stats.get(key)

  :param string key: i.e. ``"queries"``
  :return: ``number``

Return nominal value of given key. 

.. function:: stats.set(key, val)

  :param string key:  i.e. ``"queries"``
  :param number val:  i.e. ``5``

Set nominal value of given key.

