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
There is also a support for writing modules in Go 1.5+ |---| the library has no native Go bindings, library is accessible using CGO_.

The anatomy of an extension
===========================

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
This doesn't apply for Go, as it for now always implements `main` and requires capitalized first letter in order to export its symbol.

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
if ``state == kres.FAIL`` (note that ``finalize`` and ``finish`` does get called nevertheless).

Since the modules are like any other Lua modules, you can interact with them through the CLI and and any interface.

.. tip:: The module can be placed anywhere in the Lua search path, in the working directory or in the MODULESDIR.

Writing a module in C
=====================

As almost all the functions are optional, the minimal module looks like this:

.. code-block:: c

	#include "lib/module.h"
	/* Convenience macro to declare module API. */
	KR_MODULE_EXPORT(mymodule);


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

Writing a module in Go
======================

The Go modules use CGO_ to interface C resolver library, there are no native bindings yet. Second issue is that layers are declared as a structure of function pointers, which are `not present in Go`_, the workaround is to declare them in CGO_ header. Each module must be the ``main`` package, here's a minimal example:

.. code-block:: go

	package main

	/*
	#include "lib/module.h"
	*/
	import "C"
	import "unsafe"

	/* Mandatory functions */

	//export mymodule_api
	func mymodule_api() C.uint32_t {
		return C.KR_MODULE_API
	}
	func main() {}

.. warning:: Do not forget to prefix function declarations with ``//export symbol_name``, as only these will be exported in module.

In order to integrate with query processing, you have to declare a helper function with function pointers to the
the layer implementation. Since the code prefacing ``import "C"`` is expanded in headers, you need the `static inline` trick
to avoid multiple declarations. Here's how the preface looks like:

.. code-block:: go

	/*
	#include "lib/layer.h"
	#include "lib/module.h"
	// Need a forward declaration of the function signature
	int finish(kr_layer_t *);
	// Workaround for layers composition
	static inline const kr_layer_api_t *_layer(void)
	{
		static const kr_layer_api_t api = {
			.finish = &finish
		};
		return &api;
	}
	*/
	import "C"
	import "unsafe"

Now we can add the implementations for the ``finish`` layer and finalize the module:

.. code-block:: go

	//export finish
	func finish(ctx *C.kr_layer_t) C.int {
		// Since the context is unsafe.Pointer, we need to cast it
		var param *C.struct_kr_request = (*C.struct_kr_request)(ctx.data)
		// Now we can use the C API as well
		fmt.Printf("[go] resolved %d queries\n", C.list_size(&param.rplan.resolved))
		return 0
	}

	//export mymodule_layer
	func mymodule_layer(module *C.struct_kr_module) *C.kr_layer_api_t {
		// Wrapping the inline trampoline function
		return C._layer()
	}

See the CGO_ for more information about type conversions and interoperability between the C/Go.

Gotchas
-------

* ``main()`` function is mandatory in each module, otherwise it won't compile.
* Module layer function implementation must be done in C during ``import "C"``, as Go doesn't support pointers to functions.
* The library doesn't have a Go-ified bindings yet, so interacting with it requires CGO shims, namely structure traversal and type conversions (strings, numbers).
* Other modules can be called through C call ``C.kr_module_call(kr_context, module_name, module_propery, input)``

Configuring modules
===================

There is a callback ``X_config()`` that you can implement, see hints module.

.. _mod-properties:

Exposing C/Go module properties
===============================

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

.. _`not present in Go`: http://blog.golang.org/gos-declaration-syntax
.. _CGO: http://golang.org/cmd/cgo/

.. |---| unicode:: U+02014 .. em dash
