Cache control
~~~~~~~~~~~~~

Module providing an interface to cache database, for inspection, manipulation and purging.

Properties
..........

``get_size``
	Return number of cached records.

	:Input:  N/A
	:Output: ``{ size: int }``
``prune``
	Prune expired/invalid records.

	:Input:  N/A
	:Output: ``{ pruned: int }``
``clear``
	Clear all cache records.

 	:Input:  N/A
 	:Output: ``{ result: bool }``
