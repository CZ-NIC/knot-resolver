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

The root anchors bootstrap may fail for various reasons, in this case you need to provide IANA or alternative root anchors. The format of the keyfile is the same as for Unbound or BIND and contains DS/DNSKEY records.

1. Check the current TA published on `IANA website <https://data.iana.org/root-anchors/root-anchors.xml>`_
2. Fetch current keys (DNSKEY), verify digests
3. Deploy them

.. code-block:: bash

   $ kdig DNSKEY . @k.root-servers.net +noall +answer | grep "DNSKEY[[:space:]]257" > root.keys
   $ ldns-key2ds -n root.keys # Only print to stdout
   ... verify that digest matches TA published by IANA ...
   $ kresd -k root.keys

You've just enabled DNSSEC!

CLI interface
=============

The daemon features a CLI interface, type ``help()`` to see the list of available commands.

.. code-block:: bash

   $ kresd /var/run/knot-resolver
   [system] started in interactive mode, type 'help()'
   > cache.count()
   53

.. role:: lua(code)
   :language: lua

Verbose output
--------------

If the verbose logging is compiled in, i.e. not turned off by ``-DNOVERBOSELOG``, you can turn on verbose tracing of server operation with the ``-v`` option.
You can also toggle it on runtime with ``verbose(true|false)`` command.

.. code-block:: bash

   $ kresd -v

Scaling out
===========

The server can clone itself into multiple processes upon startup, this enables you to scale it on multiple cores.
Multiple processes can serve different addresses, but still share the same working directory and cache.
You can add, start and stop processes during runtime based on the load.

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

.. note:: On recent Linux supporting ``SO_REUSEPORT`` (since 3.9, backported to RHEL 2.6.32) it is also able to bind to the same endpoint and distribute the load between the forked processes. If your OS doesn't support it, you can :ref:`use supervisor <daemon-supervised>` that is going to bind to sockets before starting multiple processes.

Notice the absence of an interactive CLI. You can attach to the the consoles for each process, they are in ``rundir/tty/PID``.

.. code-block:: bash

	$ nc -U rundir/tty/3008 # or socat - UNIX-CONNECT:rundir/tty/3008
	> cache.count()
	53

The *direct output* of the CLI command is captured and sent over the socket, while also printed to the daemon standard outputs (for accountability). This gives you an immediate response on the outcome of your command.
Error or debug logs aren't captured, but you can find them in the daemon standard outputs.

This is also a way to enumerate and test running instances, the list of files in ``tty`` corresponds to the list
of running processes, and you can test the process for liveliness by connecting to the UNIX socket.

.. _daemon-supervised:

Running supervised
==================

Knot Resolver can run under a supervisor to allow for graceful restarts, watchdog process and socket activation. This way the supervisor binds to sockets and lends them to the resolver daemon. If the resolver terminates or is killed, the sockets remain open and no queries are dropped.

The watchdog process must notify kresd about active file descriptors, and kresd will automatically determine the socket type and bound address, thus it will appear as any other address. There's a tiny supervisor script for convenience, but you should have a look at `real process managers`_.

.. code-block:: bash

   $ python scripts/supervisor.py ./daemon/kresd -a 127.0.0.1
   $ [system] interactive mode
   > quit()
   > [2016-03-28 16:06:36.795879] process finished, pid = 99342, status = 0, uptime = 0:00:01.720612
   [system] interactive mode
   >

The daemon also supports `systemd socket activation`_, it is automatically detected and requires no configuration on users's side.

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
   modules = { 'policy' }
   -- 10MB cache
   cache.size = 10*MB

.. tip:: There are more configuration examples in `etc/` directory for personal, ISP, company internal and resolver cluster use cases.

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

If the module accepts configuration, you can call the ``module.config({...})`` or provide options table.
The syntax for table is ``{ key1 = value, key2 = value }``, and it represents the unpacked `JSON-encoded`_ string, that
the modules use as the :ref:`input configuration <mod-properties>`.

.. code-block:: lua

	modules = {
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

Knowing that the the configuration is a Lua in disguise enables you to write dynamic rules. It also helps you to avoid repetitive templating that is unavoidable with static configuration.

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

.. tip:: Some users observed a considerable, close to 100%, performance gain in Docker containers when they bound the daemon to a single interface:ip address pair. One may expand the aforementioned example with browsing available addresses as:

	.. code-block:: lua

		addrpref = env.EXPECTED_ADDR_PREFIX
		for k, v in pairs(addr_list["addr"]) do
			if string.sub(v,1,string.len(addrpref)) == addrpref then
				net.listen(v)
		...

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
		cache.prune()
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
			cache.prune()
			-- cancel event on 5th attempt
			i = i + 1
			if i == 5 then
				event.cancel(e)
			fi
		end
	end

	-- make recurrent event that will cancel after 5 times
	event.recurrent(5 * minute, pruner())

Another type of actionable event is activity on a file descriptor. This allows you to embed other
event loops or monitor open files and then fire a callback when an activity is detected.
This allows you to build persistent services like HTTP servers or monitoring probes that cooperate
well with the daemon internal operations.

For example a simple web server that doesn't block:

.. code-block:: lua

   local server, headers = require 'http.server', require 'http.headers'
   local cqueues = require 'cqueues'
   -- Start socket server
   local s = server.listen { host = 'localhost', port = 8080 }
   assert(s:listen())
   -- Compose per-request coroutine
   local cq = cqueues.new()
   cq:wrap(function()
      s:run(function(stream)
         -- Create response headers
         local headers = headers.new()
         headers:append(':status', '200')
         headers:append('connection', 'close')
         -- Send response and close connection
         assert(stream:write_headers(headers, false))
         assert(stream:write_chunk('OK', true))
         stream:shutdown()
         stream.connection:shutdown()
      end)
      s:close()
   end)
   -- Hook to socket watcher
   event.socket(cq:pollfd(), function (ev, status, events)
      cq:step(0)
   end)

* File watchers

.. note:: Work in progress, come back later!

.. _closures: https://www.lua.org/pil/6.1.html

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

.. function:: hostname([fqdn])

   :return: Machine hostname.

   If called with a parameter, it will set kresd's internal
   hostname. If called without a parameter, it will return kresd's
   internal hostname, or the system's POSIX hostname (see
   gethostname(2)) if kresd's internal hostname is unset.
	    
.. function:: verbose(true | false)

   :return: Toggle verbose logging.

.. function:: mode('strict' | 'normal' | 'permissive')

   :return: Change resolver strictness checking level.

   By default, resolver runs in *normal* mode. There are possibly many small adjustments
   hidden behind the mode settings, but the main idea is that in *permissive* mode, the resolver
   tries to resolve a name with as few lookups as possible, while in *strict* mode it spends much
   more effort resolving and checking referral path. However, if majority of the traffic is covered
   by DNSSEC, some of the strict checking actions are counter-productive.

   .. csv-table::
    :header: "Action", "Modes"

    "Use mandatory glue", "strict, normal, permissive"
    "Use in-bailiwick glue", "normal, permissive"
    "Use any glue records", "permissive"

.. function:: reorder_RR([true | false])

   :param boolean value: New value for the option *(optional)*
   :return: The (new) value of the option

   If set, resolver will vary the order of resource records within RR-sets
   every time when answered from cache.  It is disabled by default.

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
   :param function callback: Callback to be executed when resolution completes (e.g. `function cb (pkt, req) end`). The callback gets a packet containing the final answer and doesn't have to return anything.
   :return: boolean

   Example:

   .. code-block:: lua

      -- Send query for root DNSKEY, ignore cache
      resolve('.', kres.type.DNSKEY, kres.class.IN, kres.query.NO_CACHE)

      -- Query for AAAA record
      resolve('example.com', kres.type.AAAA, kres.class.IN, 0,
      function (answer, req)
         -- Check answer RCODE
         local pkt = kres.pkt_t(answer)
         if pkt:rcode() == kres.rcode.NOERROR then
            -- Print matching records
            local records = pkt:section(kres.section.ANSWER)
            for i = 1, #records do
               local rr = records[i]
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

.. function:: net.listen(addresses, [port = 53, flags = {tls = (port == 853)}])

   :return: boolean

   Listen on addresses; port and flags are optional.
   The addresses can be specified as a string or device,
   or a list of addresses (recursively).
   The command can be given multiple times, but note that it silently skips
   any addresses that have already been bound.

   Examples:

   .. code-block:: lua

	net.listen('::1')
	net.listen(net.lo, 5353)
	net.listen({net.eth0, '127.0.0.1'}, 53853, {tls = true})

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

   Get/set maximum EDNS payload available. Default is 4096.
   You cannot set less than 512 (512 is DNS packet size without EDNS, 1220 is minimum size for DNSSEC) or more than 65535 octets.

   Example output:

   .. code-block:: lua

	> net.bufsize 4096
	> net.bufsize()
	4096

.. function:: net.tcp_pipeline([len])

   Get/set per-client TCP pipeline limit (number of outstanding queries that a single client connection can make in parallel). Default is 50.

   .. code-block:: lua

      > net.tcp_pipeline()
      50
      > net.tcp_pipeline(100)

.. function:: net.tls([cert_path], [key_path])

   Get/set path to a server TLS certificate and private key for DNS/TLS.

   Example output:

   .. code-block:: lua

      > net.tls("/etc/kresd/server-cert.pem", "/etc/kresd/server-key.pem")
      > net.tls()
      ("/etc/kresd/server-cert.pem", "/etc/kresd/server-key.pem")
      > net.listen("::", 853)
      > net.listen("::", 443, {tls = true})

.. function:: net.tls_padding([padding])

   Get/set EDNS(0) padding.  If set to value >= 2 it will pad the answers
   to nearest *padding* boundary, e.g. if set to `64`, the answer will
   have size of multiplies of 64 (64, 128, 192, ...).  Setting padding to
   value < 2 will disable it.

.. function:: net.outgoing_v4([string address])

   Get/set the IPv4 address used to perform queries.  There is also ``net.outgoing_v6`` for IPv6.
   The default is ``nil``, which lets the OS choose any address.

Trust anchors and DNSSEC
^^^^^^^^^^^^^^^^^^^^^^^^

.. envvar:: trust_anchors.hold_down_time = 30 * day

   :return: int (default: 30 * day)

   Modify RFC5011 hold-down timer to given value. Example: ``30 * sec``

.. envvar:: trust_anchors.refresh_time = nil

   :return: int (default: nil)

   Modify RFC5011 refresh timer to given value (not set by default), this will force trust anchors
   to be updated every N seconds periodically instead of relying on RFC5011 logic and TTLs.
   Example: ``10 * sec``

.. envvar:: trust_anchors.keep_removed = 0

   :return: int (default: 0)

   How many ``Removed`` keys should be held in history (and key file) before being purged.
   Note: all ``Removed`` keys will be purged from key file after restarting the process.

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

		modules = {
			hints = {file = '/etc/hosts'}
		}

         Equals to:

         .. code-block:: lua

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

The default cache in Knot DNS Resolver is persistent with LMDB backend, this means that the daemon doesn't lose
the cached data on restart or crash to avoid cold-starts. The cache may be reused between cache
daemons or manipulated from other processes, making for example synchronised load-balanced recursors possible.

.. envvar:: cache.size (number)

   Set the cache maximum size in bytes. Note that this is only a hint to the backend,
   which may or may not respect it. See :func:`cache.open()`.

   .. code-block:: lua

	cache.size = 100 * MB -- equivalent to `cache.open(100 * MB)`

.. envvar:: cache.current_size (number)

   Get the maximum size in bytes.

   .. code-block:: lua

	print(cache.current_size)

.. envvar:: cache.storage (string)

   Set the cache storage backend configuration, see :func:`cache.backends()` for
   more information. If the new storage configuration is invalid, it is not set.

   .. code-block:: lua

	cache.storage = 'lmdb://.'

.. envvar:: cache.current_storage (string)

   Get the storage backend configuration.

   .. code-block:: lua

	print(cache.storage)

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

   :return: Number of entries in the cache or nil on error.

.. function:: cache.close()

   :return: boolean

   Close the cache.

   .. note:: This may or may not clear the cache, depending on the used backend. See :func:`cache.clear()`. 

.. function:: cache.stats()

   Return table of statistics, note that this tracks all operations over cache, not just which
   queries were answered from cache or not.

   Example:

   .. code-block:: lua

	print('Insertions:', cache.stats().insert)

.. function:: cache.max_ttl([ttl])

  :param number ttl: maximum cache TTL (default: 6 days)
  :return: current maximum TTL

  Get or set maximum cache TTL.

  .. note:: The `ttl` value must be in range `(min_ttl, 4294967295)`.

  .. warning:: This settings applies only to currently open cache, it will not persist if the cache is closed or reopened.

  .. code-block:: lua

     -- Get maximum TTL
     cache.max_ttl()
     518400
     -- Set maximum TTL
     cache.max_ttl(172800)
     172800

.. function:: cache.min_ttl([ttl])

  :param number ttl: minimum cache TTL (default: 0)
  :return: current maximum TTL

  Get or set minimum cache TTL. Any entry inserted into cache with TTL lower than minimal will be overriden to minimum TTL. Forcing TTL higher than specified violates DNS standards, use with care.

  .. note:: The `ttl` value must be in range `<0, max_ttl)`.

  .. warning:: This settings applies only to currently open cache, it will not persist if the cache is closed or reopened.

  .. code-block:: lua

     -- Get minimum TTL
     cache.min_ttl()
     0
     -- Set minimum TTL
     cache.min_ttl(5)
     5

.. function:: cache.prune([max_count])

  :param number max_count:  maximum number of items to be pruned at once (default: 65536)
  :return: ``{ pruned: int }``

  Prune expired/invalid records.

.. function:: cache.get([domain])

  :return: list of matching records in cache

  Fetches matching records from cache. The **domain** can either be:

  - a domain name (e.g. ``"domain.cz"``)
  - a wildcard (e.g. ``"*.domain.cz"``)

  The domain name fetches all records matching this name, while the wildcard matches all records at or below that name.

  You can also use a special namespace ``"P"`` to purge NODATA/NXDOMAIN matching this name (e.g. ``"domain.cz P"``).

  .. note:: This is equivalent to ``cache['domain']`` getter.

  Examples:

  .. code-block:: lua

     -- Query cache for 'domain.cz'
     cache['domain.cz']
     -- Query cache for all records at/below 'insecure.net'
     cache['*.insecure.net']

.. function:: cache.clear([domain])

  :return: ``bool``

  Purge cache records. If the domain isn't provided, whole cache is purged. See *cache.get()* documentation for subtree matching policy.

  Examples:

  .. code-block:: lua

     -- Clear records at/below 'bad.cz'
     cache.clear('*.bad.cz')
     -- Clear packet cache
     cache.clear('*. P')
     -- Clear whole cache
     cache.clear()


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

.. function:: event.reschedule(event_id, timeout)

   Reschedule a running event, it has no effect on canceled events.
   New events may reuse the event_id, so the behaviour is undefined if the function
   is called after another event is started.

   Example:

   .. code-block:: lua

      local interval = 1 * minute
      event.after(1 * minute, function (ev)
         print('Good morning!')
         -- Halven the interval for each iteration
         interval = interval / 2
         event.reschedule(ev, interval)
      end)

.. function:: event.cancel(event_id)

   Cancel running event, it has no effect on already canceled events.
   New events may reuse the event_id, so the behaviour is undefined if the function
   is called after another event is started.

   Example:

   .. code-block:: lua

      e = event.after(1 * minute, function() print('Hi!') end)
      event.cancel(e)

Watch for file descriptor activity. This allows embedding other event loops or simply
firing events when a pipe endpoint becomes active. In another words, asynchronous
notifications for daemon.

.. function:: event.socket(fd, cb)

   :param number fd: file descriptor to watch
   :param cb: closure or callback to execute when fd becomes active
   :return: event id

   Execute function when there is activity on the file descriptor and calls a closure
   with event id as the first parameter, status as second and number of events as third.

   Example:

   .. code-block:: lua

      e = event.socket(0, function(e, status, nevents)
         print('activity detected')
      end)
      e.cancel(e)

Map over multiple forks
^^^^^^^^^^^^^^^^^^^^^^^

When daemon is running in forked mode, each process acts independently. This is good because it reduces software complexity and allows for runtime scaling, but not ideal because of additional operational burden.
For example, when you want to add a new policy, you'd need to add it to either put it in the configuration, or execute command on each process independently. The daemon simplifies this by promoting process group leader which is able to execute commands synchronously over forks.

.. function:: map(expr)

   Run expression synchronously over all forks, results are returned as a table ordered as forks. Expression can be any valid expression in Lua.


   Example:

   .. code-block:: lua

      -- Current instance only
      hostname()
      localhost
      -- Mapped to forks
      map 'hostname()'
      [1] => localhost
      [2] => localhost
      -- Get worker ID from each fork
      map 'worker.id'
      [1] => 0
      [2] => 1
      -- Get cache stats from each fork
      map 'cache.stats()'
      [1] => {
          [hit] => 0
          [delete] => 0
          [miss] => 0
          [insert] => 0
      }
      [2] => {
          [hit] => 0
          [delete] => 0
          [miss] => 0
          [insert] => 0
      }

Scripting worker
^^^^^^^^^^^^^^^^

Worker is a service over event loop that tracks and schedules outstanding queries,
you can see the statistics or schedule new queries. It also contains information about
specified worker count and process rank.

.. envvar:: worker.count

   Return current total worker count (e.g. `1` for single-process)

.. envvar:: worker.id

   Return current worker ID (starting from `0` up to `worker.count - 1`)


.. envvar:: pid (number)

   Current worker process PID.


.. function:: worker.stats()

   Return table of statistics.

   * ``udp`` - number of outbound queries over UDP
   * ``tcp`` - number of outbound queries over TCP
   * ``ipv6`` - number of outbound queries over IPv6
   * ``ipv4`` - number of outbound queries over IPv4
   * ``timeout`` - number of timeouted outbound queries
   * ``concurrent`` - number of concurrent queries at the moment
   * ``queries`` - number of inbound queries
   * ``dropped`` - number of dropped inbound queries

   Example:

   .. code-block:: lua

	print(worker.stats().concurrent)

Using CLI tools
===============

* ``kresd-host.lua`` - a drop-in replacement for *host(1)* utility

Queries the DNS for information.
The hostname is looked up for IP4, IP6 and mail.

Example:

.. code-block:: bash

	$ kresd-host.lua -f root.key -v nic.cz
	nic.cz. has address 217.31.205.50 (secure)
	nic.cz. has IPv6 address 2001:1488:0:3::2 (secure)
	nic.cz. mail is handled by 10 mail.nic.cz. (secure)
	nic.cz. mail is handled by 20 mx.nic.cz. (secure)
	nic.cz. mail is handled by 30 bh.nic.cz. (secure)

* ``kresd-query.lua`` - run the daemon in zero-configuration mode, perform a query and execute given callback.

This is useful for executing one-shot queries and hooking into the processing of the result,
for example to check if a domain is managed by a certain registrar or if it's signed.

Example:

.. code-block:: bash

	$ kresd-query.lua www.sub.nic.cz 'assert(kres.dname2str(req:resolved().zone_cut.name) == "nic.cz.")' && echo "yes"
	yes
	$ kresd-query.lua -C 'trust_anchors.config("root.keys")' nic.cz 'assert(req:resolved():hasflag(kres.query.DNSSEC_WANT))'
	$ echo $?
	0

.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _LuaRocks: https://rocks.moonscript.org/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _luasec: https://luarocks.org/modules/brunoos/luasec
.. _luasocket: https://luarocks.org/modules/luarocks/luasocket
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`systemd socket activation`: http://0pointer.de/blog/projects/socket-activation.html
