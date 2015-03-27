Daemon configuration
--------------------

The Knot DNS Resolver daemon has no traditional concept of static configuration.
In it's simplest form it requires just a working directory in which it can set up persistent files like
cache and the process state.

.. code-block:: sh

	$ kresolved /var/run/kresolved

And you're good to go!

Introduction
~~~~~~~~~~~~

There are several choices on how you can configure the daemon, a RPC interface a CLI or a configuration file,
but fortunately all share a common syntax and are transparent to each other, e.g. if you change a knob, you're going to
see it projected to other interfaces as well.

.. note:: Expect this page to change a lot, as it's still just a proof of concept implementation.

Configuration 101
~~~~~~~~~~~~~~~~~

If there is a `config` file in the daemon working directory, it's going to get loaded automatically, if there isn't one
the daemon is going to start with sane defaults and listening on `localhost`. The syntax for options is like follows: ``group.option = value``
or ``group.action(parameters)``. You can also comment using a ``--`` prefix.

A simple example would be to increase the cache size.

.. code-block:: lua

	-- increase the cache to 100MB
	cache.open(".", 100*1024*1024)

Dynamic configuration
~~~~~~~~~~~~~~~~~~~~~

Packages and services
~~~~~~~~~~~~~~~~~~~~~

The Lua supports a concept called closures, this is extremely useful for scripting actions upon various events.

.. note:: TODO, come back later!

* Timers and events
* File watchers
* Serialization
* Data I/O

