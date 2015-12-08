
************************
Knot DNS Resolver daemon 
************************

The server is in the `daemon` directory, it works out of the box without any configuration.

.. code-block:: bash

   $ kresd -h # Get help
   $ kresd -a ::1

Enabling DNSSEC
===============

The resolver supports DNSSEC including :rfc:`5011` automated DNSSEC TA updates and :rfc:`7646` negative trust anchors.
To enable it, you need to provide trusted root keys. Bootstrapping of the keys is automated, and kresd fetches root trust anchors set `over a secure channel <http://jpmens.net/2015/01/21/opendnssec-rfc-5011-bind-and-unbound/>`_ from IANA. From there, it can perform :rfc:`5011` automatic updates for you.

.. note:: Automatic bootstrap requires luasocket_ and luasec_ installed.

.. code-block:: bash

   $ kresd -k root.keys # File for root keys
   [ ta ] bootstrapped root anchor "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
   [ ta ] warning: you SHOULD check the key manually, see: https://data.iana.org/root-anchors/draft-icann-dnssec-trust-anchor.html#sigs
   [ ta ] key: 19036 state: Valid
   [ ta ] next refresh: 86400000

Alternatively, you can set it in configuration file with ``trust_anchors.file = 'root.keys'``. If the file doesn't exist, it will be automatically populated with root keys validated using root anchors retrieved over HTTPS.

This is equivalent to `using unbound-anchor <https://www.unbound.net/documentation/howto_anchor.html>`_:

.. code-block:: bash

   $ unbound-anchor -a "root.keys" || echo "warning: check the key at this point"
   $ echo "auto-trust-anchor-file: \"root.keys\"" >> unbound.conf
   $ unbound -c unbound.conf

.. warning:: Bootstrapping of the root trust anchors is automatic, you are however **encouraged to check** the key over **secure channel**, as specified in `DNSSEC Trust Anchor Publication for the Root Zone <https://data.iana.org/root-anchors/draft-icann-dnssec-trust-anchor.html#sigs>`_. This is a critical step where the whole infrastructure may be compromised, you will be warned in the server log.

Manually providing root anchors
-------------------------------

The root anchors bootstrap may fail for various reasons, in this case you need to provide IANA or alternative root anchors. The format of the keyfile is the same as for Unbound or BIND and contains DNSKEY records.

1. Check the current TA published on `IANA website <https://data.iana.org/root-anchors/root-anchors.xml>`_
2. Fetch current keys (DNSKEY), verify digests
3. Deploy them

.. code-block:: bash

   $ kdig DNSKEY . @a.root-servers.net +noall +answer | grep 257 > root.keys
   $ ldns-key2ds -n root.keys # Only print to stdout
   ... verify that digest matches TA published by IANA ...
   $ kresd -k root.keys

You've just enabled DNSSEC!

CLI interface
=============

The daemon features a CLI interface, type ``help`` to see the list of available commands.

.. code-block:: bash

   $ kresd /var/run/knot-resolver
   [system] started in interactive mode, type 'help()'
   > cache.count()
   53

.. role:: lua(code)
   :language: lua

Verbose output
--------------

If the debug logging is compiled in, you can turn on verbose tracing of server operation with the ``-v`` option.
You can also toggle it on runtime with ``verbose(true|false)`` command.

.. code-block:: bash

   $ kresd -v

Scaling out
===========

The server can clone itself into multiple processes upon startup, this enables you to scale it on multiple cores.
Multiple processes can serve different addresses, but still share the same working directory and cache.
You can add start and stop processes on runtime based on the load.

.. code-block:: bash

   $ kresd -f 4 rundir > kresd.log &
   $ kresd -f 2 rundir > kresd_2.log & # Extra instances
   $ pstree $$ -g
   bash(3533)─┬─kresd(19212)─┬─kresd(19212)
              │              ├─kresd(19212)
              │              └─kresd(19212)
              ├─kresd(19399)───kresd(19399)
              └─pstree(19411)
   $ kill 19399 # Kill group 2, former will continue to run
   bash(3533)─┬─kresd(19212)─┬─kresd(19212)
              │              ├─kresd(19212)
              │              └─kresd(19212)
              └─pstree(19460)  

.. _daemon-reuseport:

.. note:: On recent Linux supporting ``SO_REUSEPORT`` (since 3.9, backported to RHEL 2.6.32) it is also able to bind to the same endpoint and distribute the load between the forked processes. If the kernel doesn't support it, you can still fork multiple processes on different ports, and do load balancing externally (on firewall or with `dnsdist <http://dnsdist.org/>`_).

Notice the absence of an interactive CLI. You can attach to the the consoles for each process, they are in ``rundir/tty/PID``.

.. code-block:: bash

	$ nc -U rundir/tty/3008 # or socat - UNIX-CONNECT:rundir/tty/3008
	> cache.count()
	53

The *direct output* of the CLI command is captured and sent over the socket, while also printed to the daemon standard outputs (for accountability). This gives you an immediate response on the outcome of your command.
Error or debug logs aren't captured, but you can find them in the daemon standard outputs.

This is also a way to enumerate and test running instances, the list of files int ``tty`` correspond to list
of running processes, and you can test the process for liveliness by connecting to the UNIX socket.

.. warning:: This is very basic way to orchestrate multi-core deployments and doesn't scale in multi-node clusters. Keep an eye on the prepared ``hive`` module that is going to automate everything from service discovery to deployment and consistent configuration.

Configuration
=============

.. contents::
   :depth: 2
   :local:

In it's simplest form it requires just a working directory in which it can set up persistent files like
cache and the process state. If you don't provide the working directory by parameter, it is going to make itself
comfortable in the current working directory.

.. code-block:: sh

	$ kresd /var/run/kresd

And you're good to go for most use cases! If you want to use modules or configure daemon behavior, read on.

There are several choices on how you can configure the daemon, a RPC interface, a CLI, and a configuration file.
Fortunately all share common syntax and are transparent to each other.

Configuration example
---------------------
.. code-block:: lua

   -- interfaces
   net = { '127.0.0.1', '::1' }
   -- load some modules
   modules = { 'policy', 'cachectl' }
   -- 10MB cache
   cache.size = 10*MB

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
		hints = '/etc/hosts'
	}

.. warning:: Modules specified including their configuration may not load exactly in the same order as specified.

Modules are inherently ordered by their declaration. Some modules are built-in, so it would be normally impossible to place for example *hints* before *rrcache*. You can enforce specific order by precedence operators **>** and **<**.

.. code-block:: lua

   modules = {
      'hints  > iterate', -- Hints AFTER iterate
      'policy > hints',   -- Policy AFTER hints
      'view   < rrcache'  -- View BEFORE rrcache
   }
   modules.list() -- Check module call order

This is useful if you're writing a module with a layer, that evaluates an answer before writing it into cache for example.

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
		cache.size = 100*MB
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

.. function:: verbose(true | false)

   :return: Toggle verbose logging.

.. function:: user(name, [group])

   :param string name: user name
   :param string group: group name (optional)
   :return: boolean

   Drop privileges and run as given user (and group, if provided).

   .. tip:: Note that you should bind to required network addresses before changing user. At the same time, you should open the cache **AFTER** you change the user (so it remains accessible). A good practice is to divide configuration in two parts:

      .. code-block:: lua

         -- privileged
         net = { '127.0.0.1', '::1' }
         -- unprivileged
         cache.size = 100*MB
         trust_anchors.file = 'root.key'

   Example output:

   .. code-block:: lua

      > user('baduser')
      invalid user name
      > user('kresd', 'netgrp')
      true
      > user('root')
      Operation not permitted

.. function:: resolve(qname, qtype[, qclass = kres.class.IN, options = 0, callback = nil])

   :param string qname: Query name (e.g. 'com.')
   :param number qtype: Query type (e.g. ``kres.type.NS``)
   :param number qclass: Query class *(optional)* (e.g. ``kres.class.IN``)
   :param number options: Resolution options (see query flags)
   :param function callback: Callback to be executed when resolution completes (e.g. `function cb (pkt) end`). The callback gets a packet containing the final answer and doesn't have to return anything.
   :return: boolean

   Example:

   .. code-block:: lua

      -- Send query for root DNSKEY, ignore cache
      resolve('.', kres.type.DNSKEY, kres.class.IN, kres.query.NO_CACHE)

      -- Query for AAAA record
      resolve('example.com', kres.type.AAAA, kres.class.IN, 0,
      function (answer)
         -- Check answer RCODE
         local pkt = kres.pkt_t(answer)
         if pkt:rcode() == kres.rcode.NOERROR then
            -- Print matching records
            local records = pkt:section(kres.section.ANSWER)
            for i = 1, #records do
               if rr.type == kres.type.AAAA then
                  print ('record:', kres.rr2str(rr))
               end
            end
         else
            print ('rcode: ', pkt:rcode())
         end
      end)

Network configuration
^^^^^^^^^^^^^^^^^^^^^

For when listening on ``localhost`` just doesn't cut it.

.. tip:: Use declarative interface for network.

         .. code-block:: lua

            net = { '127.0.0.1', net.eth0, net.eth1.addr[1] }
            net.ipv4 = false

.. envvar:: net.ipv6 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv6 for recursion.

.. envvar:: net.ipv4 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv4 for recursion.

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

.. function:: net.bufsize([udp_bufsize])

   Get/set maximum EDNS payload available. Default is 1452 (the maximum unfragmented datagram size).
   You cannot set less than 1220 (minimum size for DNSSEC) or more than 65535 octets.

   Example output:

   .. code-block:: lua

	> net.bufsize(4096)
	> net.bufsize()
	4096

Trust anchors and DNSSEC
^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: trust_anchors.config(keyfile)

   :param string keyfile: File containing DNSKEY records, should be writeable.

   You can use only DNSKEY records in managed mode. It is equivalent to CLI parameter ``-k <keyfile>`` or ``trust_anchors.file = keyfile``.

   Example output:

   .. code-block:: lua

      > trust_anchors.config('root.keys')
      [trust_anchors] key: 19036 state: Valid

.. function:: trust_anchors.set_insecure(nta_set)

   :param table nta_list: List of domain names (text format) representing NTAs.

   When you use a domain name as an NTA, DNSSEC validation will be turned off at/below these names.
   Each function call replaces the previous NTA set. You can find the current active set in ``trust_anchors.insecure`` variable.

   .. tip:: Use the `trust_anchors.negative = {}` alias for easier configuration.

   Example output:

   .. code-block:: lua

      > trust_anchors.negative = { 'bad.boy', 'example.com' }
      > trust_anchors.insecure
      [1] => bad.boy
      [2] => example.com

.. function:: trust_anchors.add(rr_string)

   :param string rr_string: DS/DNSKEY records in presentation format (e.g. ``. 3600 IN DS 19036 8 2 49AAC11...``)

   Inserts DS/DNSKEY record(s) into current keyset. These will not be managed or updated, use it only for testing
   or if you have a specific use case for not using a keyfile.

   Example output:

   .. code-block:: lua

      > trust_anchors.add('. 3600 IN DS 19036 8 2 49AAC11...')

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

.. function:: cache.stats()

   Return table of statistics, note that this tracks all operations over cache, not just which
   queries were answered from cache or not.

   Example:

   .. code-block:: lua

	print('Insertions:', cache.stats().insert)

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

Scripting worker
^^^^^^^^^^^^^^^^

Worker is a service over event loop that tracks and schedules outstanding queries,
you can see the statistics or schedule new queries. It also contains information about
specified worker count and process rank.

.. envvar:: worker.count

   Return current total worker count (e.g. `1` for single-process)

.. envvar:: worker.id

   Return current worker ID (starting from `0` up to `worker.count - 1`)

.. function:: worker.stats()

   Return table of statistics.

   * ``udp`` - number of outbound queries over UDP
   * ``tcp`` - number of outbound queries over TCP
   * ``ipv6`` - number of outbound queries over IPv6
   * ``ipv4`` - number of outbound queries over IPv4
   * ``concurrent`` - number of concurrent queries at the moment

   Example:

   .. code-block:: lua

	print(worker.stats().concurrent)

.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _LuaRocks: https://rocks.moonscript.org/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: http://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _luasec: https://luarocks.org/modules/luarocks/luasec
.. _luasocket: https://luarocks.org/modules/luarocks/luasocket