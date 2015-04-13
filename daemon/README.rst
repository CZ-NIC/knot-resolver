************************
Knot DNS Resolver daemon 
************************

Requirements
============

* libuv_ 1.0+ (a multi-platform support library with a focus on asynchronous I/O)
* Lua_ 5.1+ (embeddable scripting language, LuaJIT_ is preferred)

Running
=======

There is a separate resolver library in the `lib` directory, and a minimalistic daemon in
the `daemon` directory.

.. code-block:: bash

	$ ./daemon/kresolved -h

Interacting with the daemon
---------------------------

The daemon features a CLI interface if launched interactively, type ``help`` to see the list of available commands.
You can load modules this way and use their properties to get information about statistics and such.

.. code-block:: bash

	$ kresolved /var/run/knot-resolver
	[system] started in interactive mode, type 'help()'
	> cache.count()
	53

.. role:: lua(code)
   :language: lua

Configuration
=============

.. contents::
   :depth: 2
   :local:

In it's simplest form it requires just a working directory in which it can set up persistent files like
cache and the process state. If you don't provide the working directory by parameter, it is going to make itself
comfortable in the current working directory.

.. code-block:: sh

	$ kresolved /var/run/kresolved

And you're good to go for most use cases! If you want to use modules or configure daemon behavior, read on.

There are several choices on how you can configure the daemon, a RPC interface a CLI and a configuration file.
Fortunately all share common syntax and are transparent to each other, e.g. changes made during the runtime are kept
in the redo log and are immediately visible.

.. warning:: Redo log is not yet implemented, changes are visible during the process lifetime only.

Configuration example
---------------------
.. code-block:: lua

	-- 10MB cache
	cache.open(10*MB)
	-- static hints
	modules = {
		hints = true,
		cachectl = true
	}
	-- interfaces
	net.listen('127.0.0.1')

Configuration syntax
--------------------

The configuration is kept in the ``config`` file in the daemon working directory, and it's going to get loaded automatically.
If there isn't one, the daemon is going to start with sane defaults, listening on `localhost`.
The syntax for options is like follows: ``group.option = value`` or ``group.action(parameters)``.
You can also comment using a ``--`` prefix.

A simple example would be to load static hints.

.. code-block:: lua

	modules = {
		cachectl = true -- no configuration
	}

If the module accepts accepts configuration, you can provide a table.
The syntax for table is ``{ key1 = value, key2 = value }``, and it represents the unpacked `JSON-encoded`_ string, that
the modules use as the :ref:`input configuration <mod-properties>`.

.. code-block:: lua

	modules = {
		cachectl = true,
		hints = {
			file = '/etc/hosts'
		}
	}

The possible simple data types are strings, integers or floats and boolean.

.. tip:: The configuration and CLI syntax is Lua language, with which you may already be familiar with.
         If not, you can read the `Learn Lua in 15 minutes`_ for a syntax overview. Spending just a few minutes
         will allow you to break from static configuration, write more efficient configuration with iteration, and
         leverage events and hooks. Lua is heavily used for scripting in applications ranging from embedded to game engines,
         but in DNS world notably in `PowerDNS Recursor`_. Knot DNS Resolver does not simply use Lua modules, but it is
         the heart of the daemon for everything from configuration, internal events and user interaction.

Dynamic configuration
^^^^^^^^^^^^^^^^^^^^^

Knowing that the the configuration is a valid Lua script enables you to write dynamic rules, and also avoid
additional configuration templating. One example is to differentiate between internal and external
interfaces based on environment variable.

.. code-block:: lua

	if hostname() == 'hidden' then
		net.listen(net.eth0)
	else
		net.listen(net.eth1.addr[1])
	end

Another example would show how it is possible to bind to all interfaces, using iteration.

.. code-block:: lua

	for name, addr_list in pairs(net.interfaces()) do
		net.listen(addr_list)
	end

You can also use third-party packages (available for example through LuaRocks_) as on this example
to download cache from parent, to avoid cold-cache start.

.. code-block:: lua

	local http = require('socket.http')
	local ltn12 = require('ltn12')

	if cache.count() == 0 then
		-- download cache from parent
		http.request { 
			url = 'http://parent/cache.mdb',
			sink = ltn12.sink.file(io.open('cache.mdb', 'w'))
		}
		-- reopen cache with 100M limit
		cache.open('.', 100*MB)
	end

Events and services
^^^^^^^^^^^^^^^^^^^

The Lua supports a concept called closures, this is extremely useful for scripting actions upon various events.

.. note:: Work in progress, come back later!

* Timers and events
* File watchers
* Data I/O


Configuration reference
-----------------------

This is a reference for variables and functions available to both configuration file and CLI.

Environment
^^^^^^^^^^^

.. envvar:: env (table)

   Return environment variable.

   .. code-block:: lua

	env.USER -- equivalent to $USER in shell

.. function:: hostname()

   :return: Machine hostname.

Network configuration
^^^^^^^^^^^^^^^^^^^^^

.. function:: net.listen(address, [port = 53])

   :return: boolean

   Listen on address, port is optional.

.. function:: net.listen({address1, ...}, [port = 53])

   :return: boolean

   Listen on list of addresses.

.. function:: net.listen(interface, [port = 53])

   :return: boolean

   Listen on all addresses belonging to an interface.

   Example:

   .. code-block:: lua

	net.listen(net.eth0) -- listen on eth0

.. function:: net.close(address, [port = 53])

   :return: boolean

   Close opened address/port pair, noop if not listening.

.. function:: net.list()

   :return: Table of bound interfaces.

   Example output:

   .. code-block:: lua

	[127.0.0.1] => {
	    [port] => 53
	    [tcp] => true
	    [udp] => true
	}

.. function:: net.interfaces()

   :return: Table of available interfaces and their addresses.

   Example output:

   .. code-block:: lua

	[lo0] => {
	    [addr] => {
	        [1] => ::1
	        [2] => 127.0.0.1
	    }
	    [mac] => 00:00:00:00:00:00
	}
	[eth0] => {
	    [addr] => {
	        [1] => 192.168.0.1
	    }
	    [mac] => de:ad:be:ef:aa:bb
	}

   .. tip:: You can use ``net.<iface>`` as a shortcut for specific interface, e.g. ``net.eth0``

Modules configuration
^^^^^^^^^^^^^^^^^^^^^

The daemon provides an interface for dynamic loading of :ref:`daemon modules <modules-implemented>`.

.. tip:: Use declarative interface for module loading.

         .. code-block:: lua

		modules = {
			hints = {file = '/etc/hosts'}
		}

         Equals to:

         .. code-block:: lua

		modules.load('cachectl')
		cachectl.config({file = '/etc/hosts'})


.. function:: modules.list()

   :return: List of loaded modules.

.. function:: modules.load(name)

   :param string name: Module name, e.g. "hints"
   :return: boolean

   Load a module by name.

.. function:: modules.unload(name)

   :param string name: Module name
   :return: boolean

   Unload a module by name.

Cache configuration
^^^^^^^^^^^^^^^^^^^

The cache in Knot DNS Resolver is persistent with LMDB backend, this means that the daemon doesn't lose
the cached data on restart or crash to avoid cold-starts. The cache may be reused between cache
daemons or manipulated from other processes, making for example synchronised load-balanced recursors possible.

.. function:: cache.open(max_size)

   :param number max_size: Maximum cache size in bytes.
   :return: boolean

   Open cache with size limit. The cache will be reopened if already open.
   Note that the max_size cannot be lowered, only increased due to how cache is implemented.

   .. tip:: Use ``kB, MB, GB`` constants as a multiplier, e.g. ``100*MB``.

.. function:: cache.count()

   :return: Number of entries in the cache.

.. function:: cache.close()

   :return: boolean

   Close the cache.

.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _LuaRocks: https://rocks.moonscript.org/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: http://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html