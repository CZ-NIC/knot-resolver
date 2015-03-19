Knot DNS Resolver daemon 
========================

Requirements
------------

* libuv_ 1.0+ (a multi-platform support library with a focus on asynchronous I/O)

Starting the daemon
-------------------

There is a separate resolver library in the `lib` directory, and a minimalistic daemon in
the `daemon` directory. The daemon accepts a few CLI parameters, and there's no support for configuration
right now.

.. code-block:: bash

	$ ./daemon/kresolved -h
	$ ./daemon/kresolved -a 127.0.0.1#53

.. _libuv: https://github.com/libuv/libuv

Interacting with the daemon
---------------------------

The daemon features a CLI interface if launched interactively, type ``help`` to see the list of available commands.
You can load modules this way and use their properties to get information about statistics and such.

.. code-block:: bash

	$ kresolved
	...
	[system] started in interactive mode, type 'help'
	> load cached
	> cached.cached_size
	{ "size": 53 }