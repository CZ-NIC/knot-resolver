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
