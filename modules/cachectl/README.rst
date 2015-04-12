Cache control
-------------

Module providing an interface to cache database, for inspection, manipulation and purging.

Properties
^^^^^^^^^^

``prune``
	Prune expired/invalid records.

	:Input:  N/A
	:Output: ``{ pruned: int }``
``clear``
	Clear all cache records.

 	:Input:  N/A
 	:Output: ``{ result: bool }``
