******
Daemon
******

The server is in the `daemon` directory, it works out of the box without any configuration.

.. code-block:: bash

   $ kresd -v  # run with defaults in verbose mode
   $ kresd -h  # Get help

If you're using our packages, they also provide systemd integration. To start the resolver under systemd, you can use the ``kresd@1.service`` service. By default, the resolver only binds to local interfaces.

.. code-block:: bash

   $ man kresd.systemd  # Help for systemd integration configuration
   $ systemctl start kresd@1.service


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

.. _async-events:

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
         trust_anchors.add_file('root.key')

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
      function (pkt, req)
         -- Check answer RCODE
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


.. include:: ../daemon/bindings/net.rst


.. _dnssec-config:

Trust anchors and DNSSEC
^^^^^^^^^^^^^^^^^^^^^^^^

Since version 4.0, **DNSSEC validation is enabled by default**.
This is secure default and should not be changed unless absolutely necessary.

**Options in this section are intended only for expert users and normally
should not be needed.**

If you really need to turn DNSSEC off and are okay with lowering security of your
system by doing so, add the following snippet to your configuration file.

.. code-block:: lua

   -- turns off DNSSEC validation
   trust_anchors.remove('.')

The resolver supports DNSSEC including :rfc:`5011` automated DNSSEC TA updates
and :rfc:`7646` negative trust anchors.  Depending on your distribution, DNSSEC
trust anchors should be either maintained in accordance with the distro-wide
policy, or automatically maintained by the resolver itself.

In practice this means that you can forget about it and your favorite Linux
distribution will take care of it for you.


.. function:: trust_anchors.add_file(keyfile[, readonly = false])

   :param string keyfile: path to the file.
   :param readonly: if true, do not attempt to update the file.

   The format is standard zone file, though additional information may be persisted in comments.
   Either DS or DNSKEY records can be used for TAs.
   If the file does not exist, bootstrapping of *root* TA will be attempted.
   If you want to use bootstrapping, install `lua-http`_ library.

   Each file can only contain records for a single domain.
   The TAs will be updated according to :rfc:`5011` and persisted in the file (if allowed).

   Example output:

   .. code-block:: lua

      > trust_anchors.add_file('root.key')
      [ ta ] new state of trust anchors for a domain:
      .                       165488  DS      19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
      nil

      [ ta ] key: 19036 state: Valid

.. function:: trust_anchors.remove(zonename)

   Remove specified trust anchor from trusted key set. Removing trust anchor for the root zone effectivelly disables DNSSEC validation (unless you configured another trust anchor).

   .. code-block:: lua

      > trust_anchors.remove('.')
      true

   If you want to disable DNSSEC validation for a particular domain but keep it enabled for the rest of DNS tree, use :func:`trust_anchors.set_insecure`.

.. envvar:: trust_anchors.hold_down_time = 30 * day

   :return: int (default: 30 * day)

   Modify RFC5011 hold-down timer to given value. Intended only for testing purposes. Example: ``30 * sec``

.. envvar:: trust_anchors.refresh_time = nil

   :return: int (default: nil)

   Modify RFC5011 refresh timer to given value (not set by default), this will force trust anchors
   to be updated every N seconds periodically instead of relying on RFC5011 logic and TTLs.
   Intended only for testing purposes.
   Example: ``10 * sec``

.. envvar:: trust_anchors.keep_removed = 0

   :return: int (default: 0)

   How many ``Removed`` keys should be held in history (and key file) before being purged.
   Note: all ``Removed`` keys will be purged from key file after restarting the process.


.. function:: trust_anchors.set_insecure(nta_set)

   :param table nta_list: List of domain names (text format) representing NTAs.

   When you use a domain name as an *negative trust anchor* (NTA), DNSSEC validation will be turned off at/below these names.
   Each function call replaces the previous NTA set. You can find the current active set in ``trust_anchors.insecure`` variable.
   If you want to disable DNSSEC validation completely use :func:`trust_anchors.remove` function instead.

   Example output:

   .. code-block:: lua

      > trust_anchors.set_insecure({ 'bad.boy', 'example.com' })
      > trust_anchors.insecure
      [1] => bad.boy
      [2] => example.com

   .. warning:: If you set NTA on a name that is not a zone cut,
      it may not always affect names not separated from the NTA by a zone cut.

.. function:: trust_anchors.add(rr_string)

   :param string rr_string: DS/DNSKEY records in presentation format (e.g. ``. 3600 IN DS 19036 8 2 49AAC11...``)

   Inserts DS/DNSKEY record(s) into current keyset. These will not be managed or updated, use it only for testing
   or if you have a specific use case for not using a keyfile.

   .. note:: Static keys are very error-prone and should not be used in production. Use :func:`trust_anchors.add_file` instead.

   Example output:

   .. code-block:: lua

      > trust_anchors.add('. 3600 IN DS 19036 8 2 49AAC11...')

.. function:: trust_anchors.summary()

   Return string with summary of configured DNSSEC trust anchors, including negative TAs.


.. include:: ../daemon/bindings/modules.rst
.. include:: ../daemon/bindings/cache.rst
.. include:: ../daemon/bindings/event.rst
.. include:: ../daemon/bindings/worker.rst

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

If the verbose logging is compiled in, i.e. not turned off by
``verbose_log=disabled``, you can turn on verbose tracing of server operation
with the ``-v`` option.  You can also toggle it on runtime with
``verbose(true|false)`` command.

.. code-block:: bash

   $ kresd -v

To run the daemon by hand, such as under ``nohup``, use ``-n`` to start in non-interactive mode. For example:

.. code-block:: bash

   $ nohup ./daemon/kresd -a 127.0.0.1 -n -v &


Control sockets
===============

Unless ran manually, knot-resolver is typically started in non-interactive mode.
The mode gets triggered by using the ``-f`` command-line parameter or by passing sockets from systemd.

You can attach to the the consoles for each process; by default they are in ``rundir/tty/$PID``.
When running kresd with systemd, you can find the location of the socket(s) using
``systemctl status kresd-control@*.socket``. Typically, these are in ``/run/knot-resolver/control@*``.

Connection to the socket can be made by ``netcat`` or ``socat`` through command line.

.. code-block:: bash

   $ nc -U rundir/tty/3008 # or socat - UNIX-CONNECT:/run/knot-resolver/control@1
   > cache.count()
   83

When successfully connected to a socket, the command line should change to something like ``>``.
Then you can interact with kresd to see configuration or set a new one.
There are some basic commands to start with.

.. code-block:: lua

   > help()            -- shows help
   > net.interfaces()  -- lists available interfaces
   > net.list()        -- lists running network services


The *direct output* of the CLI command is captured and sent over the socket, while also printed to the daemon standard outputs (for accountability). This gives you an immediate response on the outcome of your command.
Error or debug logs aren't captured, but you can find them in the daemon standard outputs.

This is also a way to enumerate and test running instances, the list of files in ``tty`` corresponds to the list
of running processes, and you can test the process for liveliness by connecting to the UNIX socket.


Utilizing multiple CPUs
=======================

The server can run in multiple independent processes, all sharing the same socket and cache. These processes can be started or stopped during runtime based on the load.

**Using systemd**

To run multiple daemons using systemd, use a different numeric identifier for
the instance, for example:

.. code-block:: bash

   $ systemctl start kresd@1.service
   $ systemctl start kresd@2.service
   $ systemctl start kresd@3.service
   $ systemctl start kresd@4.service

With the use of brace expansion, the equivalent command looks like:

.. code-block:: bash

   $ systemctl start kresd@{1..4}.service

For more details, see ``kresd.systemd(7)``.

**Daemon only**

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


Cache Garbage Collector
=======================

kresd daemon uses the available cache until it's full. When more space is
required, the entire cache is dropped. To avoid starting over with an empty
cache, a separate garbage collector daemon is available to periodically trim
the cache instead.

The cache garbage collector daemon (``kres-cache-gc``) monitors the cache usage
and attempts to free up space when a threshold is reached. A garbage collector
systemd service, ``kres-cache-gc.service`` is turned on in our upstream packages.

To spawn the daemon manually and configure it to run every second, use:

.. code-block:: bash

   $ kres-cache-gc -c /var/cache/knot-resolver -d 1000


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
	$ kresd-query.lua -C 'trust_anchors.add_file("root.keys")' nic.cz 'assert(req:resolved().flags.DNSSEC_WANT)'
	$ echo $?
	0


Code reference
==============

.. doxygenfile:: daemon/worker.h


.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _LuaRocks: https://luarocks.org/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _cqueues: https://25thandclement.com/~william/projects/cqueues.html
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`socket activation`: http://0pointer.de/blog/projects/socket-activation.html
.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy
.. _`lua-http`: https://luarocks.org/modules/daurnimator/http
