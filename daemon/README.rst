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
	cache.size = 10*MB
	-- load some modules
	modules = { 'hints', 'cachectl' }
	-- interfaces
	net = { '127.0.0.1' }

Configuration syntax
--------------------

The configuration is kept in the ``config`` file in the daemon working directory, and it's going to get loaded automatically.
If there isn't one, the daemon is going to start with sane defaults, listening on `localhost`.
The syntax for options is like follows: ``group.option = value`` or ``group.action(parameters)``.
You can also comment using a ``--`` prefix.

A simple example would be to load static hints.

.. code-block:: lua

	modules = {
		'hints' -- no configuration
	}

If the module accepts accepts configuration, you can call the ``module.config({...})`` or provide options table.
The syntax for table is ``{ key1 = value, key2 = value }``, and it represents the unpacked `JSON-encoded`_ string, that
the modules use as the :ref:`input configuration <mod-properties>`.

.. code-block:: lua

	modules = {
		cachectl = true,
		hints = { -- with configuration
			file = '/etc/hosts'
		}
	}

The possible simple data types are: string, integer or float, and boolean.

.. tip:: The configuration and CLI syntax is Lua language, with which you may already be familiar with.
         If not, you can read the `Learn Lua in 15 minutes`_ for a syntax overview. Spending just a few minutes
         will allow you to break from static configuration, write more efficient configuration with iteration, and
         leverage events and hooks. Lua is heavily used for scripting in applications ranging from embedded to game engines,
         but in DNS world notably in `PowerDNS Recursor`_. Knot DNS Resolver does not simply use Lua modules, but it is
         the heart of the daemon for everything from configuration, internal events and user interaction.

Dynamic configuration
^^^^^^^^^^^^^^^^^^^^^

Knowing that the the configuration is a Lua in disguise enables you to write dynamic rules, and also avoid
repetition and templating. This is unavoidable with static configuration, e.g. when you want to configure
each node a little bit differently.

.. code-block:: lua

	if hostname() == 'hidden' then
		net.listen(net.eth0, 5353)
	else
		net = { '127.0.0.1', net.eth1.addr[1] }
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
		cache.open(100*MB)
	end

Events and services
^^^^^^^^^^^^^^^^^^^

The Lua supports a concept called closures_, this is extremely useful for scripting actions upon various events,
say for example - prune the cache within minute after loading, publish statistics each 5 minutes and so on.
Here's an example of an anonymous function with :func:`event.recurrent()`:

.. code-block:: lua

	-- every 5 minutes
	event.recurrent(5 * minute, function()
		cachectl.prune()
	end)

Note that each scheduled event is identified by a number valid for the duration of the event,
you may cancel it at any time. You can do this with anonymous functions, if you accept the event
as a parameter, but it's not very useful as you don't have any *non-global* way to keep persistent variables.

.. code-block:: lua

	-- make a closure, encapsulating counter
	function pruner()
		local i = 0
		-- pruning function
		return function(e)
			cachectl.prune()
			-- cancel event on 5th attempt
			i = i + 1
			if i == 5 then
				event.cancel(e)
			fi
		end
	end

	-- make recurrent event that will cancel after 5 times
	event.recurrent(5 * minute, pruner())

* File watchers
* Data I/O

.. note:: Work in progress, come back later!

.. _closures: http://www.lua.org/pil/6.1.html

Configuration reference
-----------------------

This is a reference for variables and functions available to both configuration file and CLI.

.. contents::
   :depth: 1
   :local:

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

For when listening on ``localhost`` just doesn't cut it.

.. tip:: Use declarative interface for network.

         .. code-block:: lua

         	net = { '127.0.0.1', net.eth0, net.eth1.addr[1] }

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

         	modules = { 'cachectl' }
		modules = {
			hints = {file = '/etc/hosts'}
		}

         Equals to:

         .. code-block:: lua

		modules.load('cachectl')
		modules.load('hints')
		hints.config({file = '/etc/hosts'})


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

.. envvar:: cache.size (number)

   Get/set the cache maximum size in bytes. Note that this is only a hint to the backend,
   which may or may not respect it. See :func:`cache.open()`.

   .. code-block:: lua

	print(cache.size)
	cache.size = 100 * MB -- equivalent to `cache.open(100 * MB)`

.. envvar:: cache.storage (string)

   Get or change the cache storage backend configuration, see :func:`cache.backends()` for
   more information. If the new storage configuration is invalid, it is not set.

   .. code-block:: lua

	print(cache.storage)
	cache.storage = 'lmdb://.'

.. function:: cache.backends()

   :return: map of backends

   The cache supports runtime-changeable backends, using the optional :rfc:`3986` URI, where the scheme
   represents backend protocol and the rest of the URI backend-specific configuration. By default, it
   is a ``lmdb`` backend in working directory, i.e. ``lmdb://``.

   Example output:

   .. code-block:: lua

   	[lmdb://] => true

.. function:: cache.stats()

   :return: table of cache counters

  The cache collects counters on various operations (hits, misses, transactions, ...). This function call returns a table of
  cache counters that can be used for calculating statistics.

.. function:: cache.open(max_size[, config_uri])

   :param number max_size: Maximum cache size in bytes.
   :return: boolean

   Open cache with size limit. The cache will be reopened if already open.
   Note that the max_size cannot be lowered, only increased due to how cache is implemented.

   .. tip:: Use ``kB, MB, GB`` constants as a multiplier, e.g. ``100*MB``.

   The cache supports runtime-changeable backends, see :func:`cache.backends()` for mor information and
   default. Refer to specific documentation of specific backends for configuration string syntax.

   - ``lmdb://``

   As of now it only allows you to change the cache directory, e.g. ``lmdb:///tmp/cachedir``.

.. function:: cache.count()

   :return: Number of entries in the cache.

.. function:: cache.close()

   :return: boolean

   Close the cache.

   .. note:: This may or may not clear the cache, depending on the used backend. See :func:`cachectl.clear()`. 

Timers and events
^^^^^^^^^^^^^^^^^

The timer represents exactly the thing described in the examples - it allows you to execute closures 
after specified time, or event recurrent events. Time is always described in milliseconds,
but there are convenient variables that you can use - ``sec, minute, hour``.
For example, ``5 * hour`` represents five hours, or 5*60*60*100 milliseconds.

.. function:: event.after(time, function)

   :return: event id

   Execute function after the specified time has passed.
   The first parameter of the callback is the event itself.

   Example:

   .. code-block:: lua

	event.after(1 * minute, function() print('Hi!') end)

.. function:: event.recurrent(interval, function)

   :return: event id

   Similar to :func:`event.after()`, periodically execute function after ``interval`` passes. 

   Example:

   .. code-block:: lua

	msg_count = 0
	event.recurrent(5 * sec, function(e) 
		msg_count = msg_count + 1
		print('Hi #'..msg_count)
	end)

.. function:: event.cancel(event_id)

   Cancel running event, it has no effect on already canceled events.
   New events may reuse the event_id, so the behaviour is undefined if the function
   is called after another event is started.

   Example:

   .. code-block:: lua

	e = event.after(1 * minute, function() print('Hi!') end)
	event.cancel(e)

.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _LuaRocks: https://rocks.moonscript.org/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: http://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html