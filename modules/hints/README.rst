.. _mod-hints:

Static hints
------------

This is a module providing static hints from ``/etc/hosts`` like file.

Properties
^^^^^^^^^^

``config``
	Load specified hosts file.

	:Input:  ``path`` i.e. ``"/etc/hosts"``
	:Output: ``{ result: bool }``

``get``
	Return list of address record matching given name.

	:Input:  ``hostname`` i.e. ``"localhost"``
	:Output: ``{ result: [address1, address2, ...] }``

``set``
	Set hostname - address hint.

 	:Input:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``
 	:Output: ``{ result: bool }``