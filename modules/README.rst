.. _modules-api:

*********************
Modules API reference
*********************

.. contents::
   :depth: 1
   :local:

Supported languages
===================

Currently modules written in C and LuaJIT are supported.

The anatomy of an extension
===========================

FIXME: review and fix.

A module is a shared object or script defining specific functions, here's an overview.

*Note* |---| the :ref:`Modules <lib_api_modules>` header documents the module loading and API.

.. csv-table::
   :header: "C/Go", "Lua", "Params", "Comment"

   "``X_api()`` [#]_", "",               "",                "API version"
   "``X_init()``",     "``X.init()``",   "``module``",      "Constructor"
   "``X_deinit()``",   "``X.deinit()``", "``module, key``", "Destructor"
   "``X_config()``",   "``X.config()``", "``module``",      "Configuration"
   "``X_layer()``",    "``X.layer``",    "``module``",      ":ref:`Module layer <lib-layers>`"
   "``X_props()``",    "",               "",                "List of properties"

.. [#] Mandatory symbol.

The ``X`` corresponds to the module name, if the module name is ``hints``, then the prefix for constructor would be ``hints_init()``.

.. note::
   The resolution context :c:type:`struct kr_context` holds loaded modules for current context. A module can be registered with :c:func:`kr_context_register`, which triggers module constructor *immediately* after the load. Module destructor is automatically called when the resolution context closes.
   
   If the module exports a layer implementation, it is automatically discovered by :c:func:`kr_resolver` on resolution init and plugged in. The order in which the modules are registered corresponds to the call order of layers.

Writing a module in Lua
=======================

The probably most convenient way of writing modules is Lua since you can use already installed modules
from system and have first-class access to the scripting engine. You can also tap to all the events, that
the C API has access to, but keep in mind that transitioning from the C to Lua function is slower than
the other way round.

.. note:: The Lua functions retrieve an additional first parameter compared to the C counterparts - a "state".
          There is no Lua wrapper for C structures used in the resolution context, until they're implemented
          you can inspect the structures using the `ffi <http://luajit.org/ext_ffi.html>`_ library.

The modules follow the `Lua way <http://lua-users.org/wiki/ModuleDefinition>`_, where the module interface is returned in a named table.

.. code-block:: lua

	--- @module Count incoming queries
	local counter = {}

	function counter.init(module)
		counter.total = 0
		counter.last = 0
		counter.failed = 0
	end

	function counter.deinit(module)
		print('counted', counter.total, 'queries')
	end

	-- @function Run the q/s counter with given interval.
	function counter.config(conf)
		-- We can use the scripting facilities here
		if counter.ev then event.cancel(counter.ev)
		event.recurrent(conf.interval, function ()
			print(counter.total - counter.last, 'q/s')
			counter.last = counter.total
		end)
	end

	return counter

.. tip:: The API functions may return an integer value just like in other languages, but they may also return a coroutine that will be continued asynchronously. A good use case for this approach is is a deferred initialization, e.g. loading a chunks of data or waiting for I/O.

.. code-block:: lua

	function counter.init(module)
		counter.total = 0
		counter.last = 0
		counter.failed = 0
		return coroutine.create(function ()
			for line in io.lines('/etc/hosts') do
				load(module, line)
				coroutine.yield()
			end
		end)
	end

The created module can be then loaded just like any other module, except it isn't very useful since it
doesn't provide any layer to capture events. The Lua module can however provide a processing layer, just
:ref:`like its C counterpart <lib-layers>`.

.. code-block:: lua

	-- Notice it isn't a function, but a table of functions
	counter.layer = {
		begin = function (state, data)
				counter.total = counter.total + 1
				return state
			end,
		finish = function (state, req, answer)
				if state == kres.FAIL then
					counter.failed = counter.failed + 1
				end
				return state
			end 
	}

There is currently an additional "feature" in comparison to C layer functions:
the ``consume``, ``produce`` and ``checkout`` functions do not get called at all
if ``state == kres.FAIL``;
note that ``answer_finalize`` and ``finish`` get called nevertheless.

Since the modules are like any other Lua modules, you can interact with them through the CLI and and any interface.

.. tip:: The module can be placed anywhere in the Lua search path, in the working directory or in the MODULESDIR.

Writing a module in C
=====================

As almost all the functions are optional, the minimal module looks like this:

.. code-block:: c

	#include "lib/module.h"
	/* Convenience macro to declare module API. */
	KR_MODULE_EXPORT(mymodule)


Let's define an observer thread for the module as well. It's going to be stub for the sake of brevity,
but you can for example create a condition, and notify the thread from query processing by declaring
module layer (see the :ref:`Writing layers <lib-layers>`).

.. code-block:: c

	static void* observe(void *arg)
	{
		/* ... do some observing ... */
	}

	int mymodule_init(struct kr_module *module)
	{
		/* Create a thread and start it in the background. */
		pthread_t thr_id;
		int ret = pthread_create(&thr_id, NULL, &observe, NULL);
		if (ret != 0) {
			return kr_error(errno);
		}

		/* Keep it in the thread */
		module->data = thr_id;
		return kr_ok();
	}

	int mymodule_deinit(struct kr_module *module)
	{
		/* ... signalize cancellation ... */
		void *res = NULL;
		pthread_t thr_id = (pthread_t) module->data;
		int ret = pthread_join(thr_id, res);
		if (ret != 0) {
			return kr_error(errno);
		}

		return kr_ok();
	}

This example shows how a module can run in the background, this enables you to, for example, observe
and publish data about query resolution.

Configuring modules
===================

There is a callback ``X_config()`` that you can implement, see hints module.

.. _mod-properties:

Exposing C module properties
============================

A module can offer NULL-terminated list of *properties*, each property is essentially a callable with free-form JSON input/output.
JSON was chosen as an interchangeable format that doesn't require any schema beforehand, so you can do two things - query the module properties
from external applications or between modules (i.e. `statistics` module can query `cache` module for memory usage).
JSON was chosen not because it's the most efficient protocol, but because it's easy to read and write and interface to outside world.

.. note:: The ``void *env`` is a generic module interface. Since we're implementing daemon modules, the pointer can be cast to ``struct engine*``.
          This is guaranteed by the implemented API version (see `Writing a module in C`_).

Here's an example how a module can expose its property:

.. code-block:: c

	char* get_size(void *env, struct kr_module *m,
	               const char *args)
	{
		/* Get cache from engine. */
		struct engine *engine = env;
        struct kr_cache *cache = &engine->resolver.cache;
		/* Read item count */
        int count = (cache->api)->count(cache->db);
		char *result = NULL;
		asprintf(&result, "{ \"result\": %d }", count);
		
		return result;
	}

	struct kr_prop *cache_props(void)
	{
		static struct kr_prop prop_list[] = {
			/* Callback,   Name,   Description */
			{&get_size, "get_size", "Return number of records."},
			{NULL, NULL, NULL}
		};
		return prop_list;
	}

	KR_MODULE_EXPORT(cache)

Once you load the module, you can call the module property from the interactive console.
*Note* |---| the JSON output will be transparently converted to Lua tables.

.. code-block:: bash

	$ kresd
	...
	[system] started in interactive mode, type 'help()'
	> modules.load('cached')
	> cached.get_size()
	[size] => 53

*Note* |---| this relies on function pointers, so the same ``static inline`` trick as for the ``Layer()`` is required for C/Go.

Special properties
------------------

If the module declares properties ``get`` or ``set``, they can be used in the Lua interpreter as
regular tables.

.. |---| unicode:: U+02014 .. em dash
