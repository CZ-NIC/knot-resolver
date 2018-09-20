************************
Knot Resolver daemon
************************

The server is in the `daemon` directory, it works out of the box without any configuration.

.. code-block:: bash

   $ kresd -h # Get help
   $ kresd -a ::1

Configuration
=============

.. contents::
   :depth: 2
   :local:

In its simplest form the server requires just a working directory in which it can set up persistent files like
cache and the process state. If you don't provide the working directory by parameter, it is going to make itself
comfortable in the current working directory.

.. code-block:: sh

	$ kresd /var/cache/knot-resolver

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

Modules are inherently ordered by their declaration. Some modules are built-in, so it would be normally impossible to place for example *hints* before *cache*. You can enforce specific order by precedence operators **>** and **<**.

.. code-block:: lua

   modules = {
      'hints  > iterate', -- Hints AFTER iterate
      'policy > hints',   -- Policy AFTER hints
      'view   < cache'    -- View BEFORE cache
   }
   modules.list() -- Check module call order

This is useful if you're writing a module with a layer, that evaluates an answer before writing it into cache for example.

.. tip:: The configuration and CLI syntax is Lua language, with which you may already be familiar with.
         If not, you can read the `Learn Lua in 15 minutes`_ for a syntax overview. Spending just a few minutes
         will allow you to break from static configuration, write more efficient configuration with iteration, and
         leverage events and hooks. Lua is heavily used for scripting in applications ranging from embedded to game engines,
         but in DNS world notably in `PowerDNS Recursor`_. Knot Resolver does not simply use Lua modules, but it is
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

        local cache_size = 100*MB
        local cache_path = '/var/cache/knot-resolver'
        cache.open(cache_size, 'lmdb://' .. cache_path)
	if cache.count() == 0 then
                cache.close()
		-- download cache from parent
		http.request {
			url = 'http://parent/data.mdb',
			sink = ltn12.sink.file(io.open(cache_path .. '/data.mdb', 'w'))
		}
		-- reopen cache with 100M limit
                cache.open(cache_size, 'lmdb://' .. cache_path)
	end

Asynchronous events
^^^^^^^^^^^^^^^^^^^

Lua supports a concept called closures_, this is extremely useful for scripting actions upon various events,
say for example - publish statistics each minute and so on.
Here's an example of an anonymous function with :func:`event.recurrent()`.

Note that each scheduled event is identified by a number valid for the duration of the event,
you may use it to cancel the event at any time.

.. code-block:: lua

        modules.load('stats')

	-- log statistics every second
	local stat_id = event.recurrent(1 * second, function(evid)
            log(table_print(stats.list()))
	end)

        -- stop printing statistics after first minute
        event.after(1 * minute, function(evid)
                event.cancel(stat_id)
        end)

If you need to persist state between events, encapsulate even handle in closure function which will provide persistent variable (called ``previous``):

.. code-block:: lua

        modules.load('stats')

	-- make a closure, encapsulating counter
        function speed_monitor()
                local previous = stats.list()
                -- monitoring function
                return function(evid)
                        local now = stats.list()
                        local total_increment = now['answer.total'] - previous['answer.total']
                        local slow_increment = now['answer.slow'] - previous['answer.slow']
                        if slow_increment / total_increment > 0.05 then
                                log('WARNING! More than 5 %% of queries was slow!')
                        end
                        previous = now  -- store current value in closure
                 end
        end

        -- monitor every minute
        local monitor_id = event.recurrent(1 * minute, speed_monitor())

Another type of actionable event is activity on a file descriptor. This allows you to embed other
event loops or monitor open files and then fire a callback when an activity is detected.
This allows you to build persistent services like HTTP servers or monitoring probes that cooperate
well with the daemon internal operations. See :func:`event.socket()`


File watchers are possible with :func:`worker.coroutine()` and cqueues_, see the cqueues documentation for more information.

.. code-block:: lua

  local notify = require('cqueues.notify')
  local watcher = notify.opendir('/etc')
  watcher:add('hosts')

  -- Watch changes to /etc/hosts
  worker.coroutine(function ()
    for flags, name in watcher:changes() do
      for flag in notify.flags(flags) do
        print(name, notify[flag])
      end
    end
  end)

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

   This affects ephemeral certificates for kresd serving DNS over TLS.

.. function:: moduledir([dir])

   :return: Modules directory.

   If called with a parameter, it will change kresd's directory for
   looking up the dynamic modules.  If called without a parameter, it
   will return kresd's modules directory.

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
    :header: "Glue type", "Modes when it is accepted",   "Example glue [#example_glue]_"

    "mandatory glue",     "strict, normal, permissive",  "ns1.example.org"
    "in-bailiwick glue",  "normal, permissive",          "ns1.example2.org"
    "any glue records",   "permissive",                  "ns1.example3.net"

   .. [#example_glue] The examples show glue records acceptable from servers
        authoritative for `org` zone when delegating to `example.org` zone.
        Unacceptable or missing glue records trigger resolution of names listed
        in NS records before following respective delegation.

.. function:: reorder_RR([true | false])

   :param boolean value: New value for the option *(optional)*
   :return: The (new) value of the option

   If set, resolver will vary the order of resource records within RR-sets.
   It is disabled by default.

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
      > user('knot-resolver', 'netgrp')
      true
      > user('root')
      Operation not permitted

.. function:: resolve(name, type[, class = kres.class.IN, options = {}, finish = nil, init = nil])

   :param string name: Query name (e.g. 'com.')
   :param number type: Query type (e.g. ``kres.type.NS``)
   :param number class: Query class *(optional)* (e.g. ``kres.class.IN``)
   :param strings options: Resolution options (see :c:type:`kr_qflags`)
   :param function finish: Callback to be executed when resolution completes (e.g. `function cb (pkt, req) end`). The callback gets a packet containing the final answer and doesn't have to return anything.
   :param function init: Callback to be executed with the :c:type:`kr_request` before resolution starts.
   :return: boolean

   The function can also be executed with a table of arguments instead. This is useful if you'd like to skip some arguments, for example:

   .. code-block:: lua

      resolve {
         name = 'example.com',
         type = kres.type.AAAA,
         init = function (req)
         end,
      }

   Example:

   .. code-block:: lua

      -- Send query for root DNSKEY, ignore cache
      resolve('.', kres.type.DNSKEY, kres.class.IN, 'NO_CACHE')

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

.. function:: package_version()

   :return: Current package version.

   This returns current package version (the version of the binary) as a string.

      .. code-block:: lua

         > package_version()
         2.1.1


Network configuration
^^^^^^^^^^^^^^^^^^^^^

For when listening on ``localhost`` just doesn't cut it.

.. tip:: Use declarative interface for network.

         .. code-block:: lua

            net = { '127.0.0.1', net.eth0, net.eth1.addr[1] }
            net.ipv4 = false

.. warning:: On machines with multiple IP addresses avoid binding to wildcard ``0.0.0.0`` or ``::`` (see example below). Knot Resolver could answer from different IP in case the ranges overlap and client will probably refuse such a response.

         .. code-block:: lua

            net = { '0.0.0.0' }


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

   .. code-block:: none

	[127.0.0.1] => {
	    [port] => 53
	    [tcp] => true
	    [udp] => true
	}

.. function:: net.interfaces()

   :return: Table of available interfaces and their addresses.

   Example output:

   .. code-block:: none

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

   Get/set per-client TCP pipeline limit, i.e. the number of outstanding queries that a single client connection can make in parallel.  Default is 100.

   .. code-block:: lua

      > net.tcp_pipeline()
      100
      > net.tcp_pipeline(50)
      50

.. function:: net.outgoing_v4([string address])

   Get/set the IPv4 address used to perform queries.  There is also ``net.outgoing_v6`` for IPv6.
   The default is ``nil``, which lets the OS choose any address.


.. _tls-server-config:

TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: net.tls([cert_path], [key_path])

   Get/set path to a server TLS certificate and private key for DNS/TLS.

   Example output:

   .. code-block:: lua

      > net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")
      > net.tls()
      ("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")
      > net.listen("::", 853)
      > net.listen("::", 443, {tls = true})

.. function:: net.tls_padding([true | false])

   Get/set EDNS(0) padding of answers to queries that arrive over TLS
   transport.  If set to `true` (the default), it will use a sensible
   default padding scheme, as implemented by libknot if available at
   compile time.  If set to a numeric value >= 2 it will pad the
   answers to nearest *padding* boundary, e.g. if set to `64`, the
   answer will have size of a multiple of 64 (64, 128, 192, ...).  If
   set to `false` (or a number < 2), it will disable padding entirely.

.. function:: net.tls_sticket_secret([string with pre-shared secret])

   Set secret for TLS session resumption via tickets, by :rfc:`5077`.

   The server-side key is rotated roughly once per hour.
   By default or if called without secret, the key is random.
   That is good for long-term forward secrecy, but multiple kresd instances
   won't be able to resume each other's sessions.

   If you provide the same secret to multiple instances, they will be able to resume
   each other's sessions *without* any further communication between them.
   This synchronization works only among instances having the same endianess
   and time_t structure and size (`sizeof(time_t)`).

   **For good security** the secret must have enough entropy to be hard to guess,
   and it should still be occasionally rotated manually and securely forgotten,
   to reduce the scope of privacy leak in case the
   `secret leaks eventually <https://en.wikipedia.org/wiki/Forward_secrecy>`_.

   .. warning:: **Setting the secret is probably too risky with TLS <= 1.2**.
      At this moment no GnuTLS stable release even supports TLS 1.3.
      Therefore setting the secrets should be considered experimental for now
      and might not be available on your system.

.. function:: net.tls_sticket_secret_file([string with path to a file containing pre-shared secret])

   The same as :func:`net.tls_sticket_secret`,
   except the secret is read from a (binary) file.

.. _dnssec-config:

Trust anchors and DNSSEC
^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: trust_anchors.config(keyfile, readonly)

   Alias for `add_file`.  It is also equivalent to CLI parameter ``-k <keyfile>``
   and ``trust_anchors.file = keyfile``.

.. function:: trust_anchors.add_file(keyfile, readonly)

   :param string keyfile: path to the file.
   :param readonly: if true, do not attempt to update the file.

   The format is standard zone file, though additional information may be persisted in comments.
   Either DS or DNSKEY records can be used for TAs.
   If the file does not exist, bootstrapping of *root* TA will be attempted.

   Each file can only contain records for a single domain.
   The TAs will be updated according to :rfc:`5011` and persisted in the file (if allowed).

   Example output:

   .. code-block:: lua

      > trust_anchors.add_file('root.key')
      [ ta ] new state of trust anchors for a domain:
      .                       165488  DS      19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
      nil

      [ ta ] key: 19036 state: Valid

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

   .. warning:: If you set NTA on a name that is not a zone cut,
      it may not always affect names not separated from the NTA by a zone cut.

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

The default cache in Knot Resolver is persistent with LMDB backend, this means that the daemon doesn't lose
the cached data on restart or crash to avoid cold-starts. The cache may be reused between cache
daemons or manipulated from other processes, making for example synchronised load-balanced recursors possible.

.. function:: cache.open(max_size[, config_uri])

   :param number max_size: Maximum cache size in bytes.
   :return: ``true`` if cache was opened

   Open cache with a size limit. The cache will be reopened if already open.
   Note that the max_size cannot be lowered, only increased due to how cache is implemented.

   .. tip:: Use ``kB, MB, GB`` constants as a multiplier, e.g. ``100*MB``.

   As of now, the built-in backend with URI ``lmdb://`` allows you to change the cache directory.

   Example:

   .. code-block:: lua

      cache.open(100 * MB, 'lmdb:///var/cache/knot-resolver')

.. envvar:: cache.size

   Set the cache maximum size in bytes. Note that this is only a hint to the backend,
   which may or may not respect it. See :func:`cache.open()`.

   .. code-block:: lua

	cache.size = 100 * MB -- equivalent to `cache.open(100 * MB)`

.. envvar:: cache.current_size

   Get the maximum size in bytes.

   .. code-block:: lua

	print(cache.current_size)

.. envvar:: cache.storage

   Set the cache storage backend configuration, see :func:`cache.backends()` for
   more information. If the new storage configuration is invalid, it is not set.

   .. code-block:: lua

	cache.storage = 'lmdb://.'

.. envvar:: cache.current_storage

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

.. function:: cache.count()

   :return: Number of entries in the cache. Meaning of the number is an implementation detail and is subject of change.

.. function:: cache.close()

   :return: ``true`` if cache was closed

   Close the cache.

   .. note:: This may or may not clear the cache, depending on the cache backend.

.. function:: cache.stats()

  .. warning:: Cache statistics are being reworked. Do not rely on current behavior.

   Return table of statistics, note that this tracks all operations over cache, not just which
   queries were answered from cache or not.

   Example:

   .. code-block:: lua

	print('Insertions:', cache.stats().insert)

.. function:: cache.max_ttl([ttl])

  :param number ttl: maximum cache TTL in seconds (default: 6 days)

  .. KR_CACHE_DEFAULT_TTL_MAX ^^

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

  :param number ttl: minimum cache TTL in seconds (default: 5 seconds)

  .. KR_CACHE_DEFAULT_TTL_MIN ^^

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

.. function:: cache.ns_tout([timeout])

  :param number timeout: NS retry interval in miliseconds (default: :c:macro:`KR_NS_TIMEOUT_RETRY_INTERVAL`)
  :return: current timeout

  Get or set time interval for which a nameserver address will be ignored after determining that it doesn't return (useful) answers.
  The intention is to avoid waiting if there's little hope; instead, kresd can immediately SERVFAIL or immediately use stale records (with :ref:`serve_stale <mod-serve_stale>` module).

  .. warning:: This settings applies only to the current kresd process.

.. function:: cache.get([domain])

  This function is not implemented at this moment.
  We plan to re-introduce it soon, probably with a slightly different API.

.. function:: cache.clear([name], [exact_name], [rr_type], [chunk_size], [callback], [prev_state])

     Purge cache records matching specified criteria. There are two specifics:

     * To reliably remove **negative** cache entries you need to clear subtree with the whole zone. E.g. to clear negative cache entries for (formerly non-existing) record `www.example.com. A` you need to flush whole subtree starting at zone apex, e.g. `example.com.` [#]_.
     * This operation is asynchonous and might not be yet finished when call to ``cache.clear()`` function returns. Return value indicates if clearing continues asynchronously or not.

  :param string name: subtree to purge; if the name isn't provided, whole cache is purged
        (and any other parameters are disregarded).
  :param bool exact_name: if set to ``true``, only records with *the same* name are removed;
                          default: false.
  :param kres.type rr_type: you may additionally specify the type to remove,
        but that is only supported with ``exact_name == true``; default: nil.
  :param integer chunk_size: the number of records to remove in one round; default: 100.
        The purpose is not to block the resolver for long.
        The default ``callback`` repeats the command after one millisecond
        until all matching data are cleared.
  :param function callback: a custom code to handle result of the underlying C call.
        Its parameters are copies of those passed to `cache.clear()` with one additional
        parameter ``rettable`` containing table with return value from current call.
        ``count`` field contains a return code from :func:`kr_cache_remove_subtree()`.
  :param table prev_state: return value from previous run (can be used by callback)

  :rtype: table
  :return: ``count`` key is always present. Other keys are optional and their presense indicate special conditions.

   * **count** *(integer)* - number of items removed from cache by this call (can be 0 if no entry matched criteria)
   * **not_apex** - cleared subtree is not cached as zone apex; proofs of non-existence were probably not removed
   * **subtree** *(string)* - hint where zone apex lies (this is estimation from cache content and might not be accurate)
   * **chunk_limit** - more than ``chunk_size`` items needs to be cleared, clearing will continue asynchonously


  Examples:

  .. code-block:: lua

     -- Clear whole cache
     > cache.clear()
     [count] => 76

     -- Clear records at and below 'com.'
     > cache.clear('com.')
     [chunk_limit] => chunk size limit reached; the default callback will continue asynchronously
     [not_apex] => to clear proofs of non-existence call cache.clear('com.')
     [count] => 100
     [round] => 1
     [subtree] => com.
     > worker.sleep(0.1)
     [cache] asynchonous cache.clear('com', false) finished

     -- Clear only 'www.example.com.'
     > cache.clear('www.example.com.', true)
     [round] => 1
     [count] => 1
     [not_apex] => to clear proofs of non-existence call cache.clear('example.com.')
     [subtree] => example.com.

.. [#] This is a consequence of DNSSEC negative cache which relies on proofs of non-existence on various owner nodes. It is impossible to efficiently flush part of DNS zones signed with NSEC3.

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

Asynchronous function execution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The `event` package provides a very basic mean for non-blocking execution - it allows running code when activity on a file descriptor is detected, and when a certain amount of time passes. It doesn't however provide an easy to use abstraction for non-blocking I/O. This is instead exposed through the `worker` package (if `cqueues` Lua package is installed in the system).

.. function:: worker.coroutine(function)

   Start a new coroutine with given function (closure). The function can do I/O or run timers without blocking the main thread. See cqueues_ for documentation of possible operations and synchronisation primitives. The main limitation is that you can't wait for a finish of a coroutine from processing layers, because it's not currently possible to suspend and resume execution of processing layers.

   Example:

   .. code-block:: lua

      worker.coroutine(function ()
        for i = 0, 10 do
          print('executing', i)
          worker.sleep(1)
        end
      end)

.. function:: worker.sleep(seconds)

   Pause execution of current function (asynchronously if running inside a worker coroutine).

When daemon is running in forked mode, each process acts independently. This is good because it reduces software complexity and allows for runtime scaling, but not ideal because of additional operational burden.
For example, when you want to add a new policy, you'd need to add it to either put it in the configuration, or execute command on each process independently. The daemon simplifies this by promoting process group leader which is able to execute commands synchronously over forks.

   Example:

   .. code-block:: lua

      worker.sleep(1)

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


.. envvar:: worker.pid

   Current worker process PID (number).


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

Running supervised
==================

Knot Resolver can run under a supervisor to allow for graceful restarts, watchdog process and socket activation. This way the supervisor binds to sockets and lends them to the resolver daemon. If the resolver terminates or is killed, the sockets remain open and no queries are dropped.

The watchdog process must notify kresd about active file descriptors, and kresd will automatically determine the socket type and bound address, thus it will appear as any other address. You should have a look at `real process managers`_.

The daemon also supports `systemd socket activation`_, it is automatically detected and requires no configuration on users's side.

See ``kresd.systemd(7)`` for details.

.. _enabling-dnssec:

Enabling DNSSEC
===============

The resolver supports DNSSEC including :rfc:`5011` automated DNSSEC TA updates and :rfc:`7646` negative trust anchors.
To enable it, you need to provide trusted root keys. Bootstrapping of the keys is automated, and kresd fetches root trust anchors set `over a secure channel <http://jpmens.net/2015/01/21/opendnssec-rfc-5011-bind-and-unbound/>`_ from IANA. From there, it can perform :rfc:`5011` automatic updates for you.

.. note:: Automatic bootstrap requires luasocket_ and luasec_ installed.

.. code-block:: none

   $ kresd -k root-new.keys # File for root keys
   [ ta ] keyfile 'root-new.keys': doesn't exist, bootstrapping
   [ ta ] Root trust anchors bootstrapped over https with pinned certificate.
          You SHOULD verify them manually against original source:
          https://www.iana.org/dnssec/files
   [ ta ] Current root trust anchors are:
   . 0 IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
   . 0 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
   [ ta ] next refresh for . in 24 hours

Alternatively, you can set it in configuration file with ``trust_anchors.file = 'root.keys'``. If the file doesn't exist, it will be automatically populated with root keys validated using root anchors retrieved over HTTPS.

This is equivalent to `using unbound-anchor <https://www.unbound.net/documentation/howto_anchor.html>`_:

.. code-block:: bash

   $ unbound-anchor -a "root.keys" || echo "warning: check the key at this point"
   $ echo "auto-trust-anchor-file: \"root.keys\"" >> unbound.conf
   $ unbound -c unbound.conf

.. warning:: Bootstrapping of the root trust anchors is automatic, you are however **encouraged to check** the key over **secure channel**, as specified in `DNSSEC Trust Anchor Publication for the Root Zone <https://data.iana.org/root-anchors/draft-icann-dnssec-trust-anchor.html#sigs>`_. This is a critical step where the whole infrastructure may be compromised, you will be warned in the server log.

Configuration is described in :ref:`dnssec-config`.

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

.. note:: Bootstrapping and automatic update need write access to keyfile direcory. If you want to manage root anchors manually you should use ``trust_anchors.add_file('root.keys', true)``.

CLI interface
=============

The daemon features a CLI interface, type ``help()`` to see the list of available commands.

.. code-block:: bash

   $ kresd /var/cache/knot-resolver
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

To run the daemon by hand, such as under ``nohup``, use ``-f 1`` to start a single fork. For example:

.. code-block:: bash

   $ nohup ./daemon/kresd -a 127.0.0.1 -f 1 -v &


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

.. note:: On recent Linux supporting ``SO_REUSEPORT`` (since 3.9, backported to RHEL 2.6.32) it is also able to bind to the same endpoint and distribute the load between the forked processes. If your OS doesn't support it, use only one daemon process.

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
	$ kresd-query.lua -C 'trust_anchors.config("root.keys")' nic.cz 'assert(req:resolved().flags.DNSSEC_WANT)'
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
.. _cqueues: https://25thandclement.com/~william/projects/cqueues.html
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`systemd socket activation`: http://0pointer.de/blog/projects/socket-activation.html
