Cache control
-------------

Module providing an interface to cache database, for inspection, manipulation and purging.

Properties
^^^^^^^^^^

.. function:: cachectl.prune()

  :return: ``{ pruned: int }``

  Prune expired/invalid records.

.. function:: cachectl.clear()

  :return: ``{ result: bool }``

  Clear all cache records.
