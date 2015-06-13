Cache control
-------------

Module providing an interface to cache database, for inspection, manipulation and purging.

Properties
^^^^^^^^^^

.. function:: cachectl.prune([max_count])

  :param number max_count:  maximum number of items to be pruned at once (default: 65536)
  :return: ``{ pruned: int }``

  Prune expired/invalid records.

.. function:: cachectl.clear()

  :return: ``{ result: bool }``

  Clear all cache records.
