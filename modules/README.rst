****************************
Knot DNS Resolver extensions
****************************

The resolver :ref:`library <lib_index>` leverages the `processing API`_ from the libknot to separate packet processing code
into layers. In order to keep the core library sane and coverable, there are only two built-in layers:
the :c:func:`iterate_layer`, and the :c:func:`itercache_layer`. The resolver context however can
load shared libraries on runtime, which allows us to build and register external modules as well.

Supported languages
-------------------

Currently modules written in C are supported.
There is also a rudimentary support for writing modules in Go |---| ⑴ the library has no native Go bindings, library is accessible using CGO_, ⑵ gc doesn't support building shared libraries, GCCGO_ is required, ⑶ no coroutines and no garbage collecting thread, as the Go code is called from C threads.

There is a plan for Lua scriptables, but it's not implemented yet.

Available services
------------------

*Note* |---| This is only crash-course in the library internals, see the resolver :ref:`library <lib_index>` documentation for the complete overview of the services.

The library offers following services:

- :ref:`Cache <lib_cache>` - MVCC cache interface for retrieving/storing resource records.
- :ref:`Resolution plan <lib_rplan>` - Query resolution plan, a list of partial queries (with hierarchy) sent in order to satisfy original query. This contains information about the queries, nameserver choice, timing information, answer and its class.
- :ref:`Nameservers <lib_nameservers>` - Reputation database of nameservers, this serves as an aid for nameserver choice.

If you're going to publish a layer in your module, it's going to be called by the query resolution driver for each query,
so you're going to work with :ref:`struct kr_layer_param <lib_api_rplan>` as your per-query context. This structure contains pointers to
resolution context, resolution plan and also the final answer. You're likely to retrieve currently solved query from the query plan:

.. code-block:: c

	int consume(knot_layer_t *ctx, knot_pkt_t *pkt)
	{
		struct kr_layer_param *param = ctx->data;
		struct kr_query *query = kr_rplan_current(param->rplan);
	}

This is only passive processing of the incoming answer. If you want to change the course of resolution, say satisfy a query from a local cache before the library issues a query to the nameserver, you can use states (see the `Static hints`_ for example).

.. code-block:: c

	int produce(knot_layer_t *ctx, knot_pkt_t *pkt)
	{
		struct kr_layer_param *param = ctx->data;
		struct kr_query *cur = kr_rplan_current(param->rplan);
		
		/* Query can be satisfied locally. */
		if (can_satisfy(cur)) {
			/* This flag makes the resolver move the query
			 * to the "resolved" list. */
			query->resolved = true;
			return KNOT_STATE_DONE;
		}

		/* Pass-through. */
		return ctx->state;
	}

It is possible to not only act during the query resolution, but also to view the complete resolution plan afterwards.
This is useful for analysis-type tasks, or *"on-resolution"* hooks.

.. code-block:: c

	int finish(knot_layer_t *ctx)
	{
		struct kr_layer_param *param = ctx->data;
		struct kr_rplan *rplan = param->rplan;

		/* Print the query sequence with start time. */
		char qname_str[KNOT_DNAME_MAXLEN];
		struct kr_query *qry = NULL
		WALK_LIST(qry, rplan->resolved) {
			knot_dname_to_str(qname_str, qry->sname, sizeof(qname_str));
			printf("%s at %u\n", qname_str, qry->timestamp);
		}

		return ctx->state;
	}

The anatomy of an extension
---------------------------

A module is a shared library defining specific functions, here's an overview of the functions.

*Note* |---| the :ref:`Modules <lib_modules>` header documents the module loading and API.

.. csv-table::
   :header: "C", "Go", "Params", "Comment"

   "``X_api()`` [#]_", "``Api()``",    "",                "Implemented API (``uint32_t``)"
   "``X_init()``",    "``Init()``",   "``module``",      "Constructor"
   "``X_deinit()``",  "``Deinit()``", "``module, key``", "Destructor"
   "``X_config()``",  "``Config()``", "``module``",      "Configuration"
   "``X_layer()``",   "``Layer()``",  "",                "Module layer"
   "``X_props()``",   "``Props()``",  "",                "NULL-terminated list of properties"

.. [#] Mandatory symbol.

The ``X_`` corresponds to the module name, if the module name is ``hints``, then the prefix for constructor would be ``hints_init()``.
This doesn't apply for Go, as it for now always implements `main` and requires capitalized first letter in order to export its symbol.

How does the module get loaded
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The resolution context :c:type:`struct kr_context` holds loaded modules for current context. A module can be registered with :c:func:`kr_context_register`, which triggers module constructor *immediately* after the load. Module destructor is automatically called when the resolution context closes.

If the module exports a layer implementation, it is automatically discovered by :c:func:`kr_resolver` on resolution init and plugged in. The order in which the modules are registered corresponds to the call order of layers.

Writing a module in C
---------------------

As almost all the functions are optional, the minimal module looks like this:

.. code-block:: c

	#include "lib/module.h"
	/* Convenience macro to declare module API. */
	KR_MODULE_EXPORT(mymodule);


Let's define an observer thread for the module as well. It's going to be stub for the sake of brevity,
but you can for example create a condition, and notify the thread from query processing by declaring
module layer (see the `Available services`_).

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
----------------------

*Note* |---| At the moment only a limited subset of Go is supported. The reason is that the Go functions must run inside the goroutines, and *presume* the garbage collector and scheduler are running in the background.
`GCCGO`_ compiler can build dynamic libraries, and also allow us to bootstrap basic Go runtime, including a trampoline to call Go functions.
The problem with the ``layer()`` and callbacks is that they're called from C threads, that Go runtime has no knowledge of.
Thus neither garbage collection or spawning routines can work. The solution could be to register C threads to Go runtime,
or have each module to run inside its world loop and use IPC instead of callbacks |---| alas neither is implemented at the moment, but may be in the future.

The Go modules also use CGO_ to interface C resolver library, and to declare layers with function pointers, which are `not present in Go`_. Each module must be the ``main`` package, here's a minimal example:

.. code-block:: go

	package main

	/*
	#include "lib/module.h"
	*/
	import "C"
	import "unsafe"

	func Api() C.uint32_t {
		return C.KR_MODULE_API
	}

In order to integrate with query processing, you have to declare a helper function with function pointers to the
the layer implementation. Since the code prefacing ``import "C"`` is expanded in headers, you need the `static inline` trick
to avoid multiple declarations. Here's how the preface looks like:

.. code-block:: go

	/*
	#include "lib/module.h"
	#include "lib/layer.h" 

	//! Trampoline for Go callbacks, note that this is going to work
	//! with ELF only, this is hopefully going to change in the future
	extern int Begin(knot_layer_t *, void *) __asm__ ("main.Begin");
	extern int Finish(knot_layer_t *) __asm__ ("main.Finish");
	static inline const knot_layer_api_t *_gostats_layer(void)
	{
		static const knot_layer_api_t api = {
			.begin = &Begin,
			.finish = &Finish
		};
		return &api;
	}
	*/
	import "C"
	import "unsafe"
	import "fmt"

Now we can add the implementations for the ``Begin`` and ``Finish`` functions, and finalize the module:

.. code-block:: go

	func Begin(ctx *C.knot_layer_t, param unsafe.Pointer) C.int {
		// Save the context
		ctx.data = param
		return 0
	}

	func Finish(ctx *C.knot_layer_t) C.int {
		// Since the context is unsafe.Pointer, we need to cast it
		var param *C.struct_kr_layer_param = (*C.struct_kr_layer_param)(ctx.data)
		// Now we can use the C API as well
		fmt.Printf("[go] resolved %d queries", C.list_size(&param.rplan.resolved))
		return 0
	}

	func Layer() *C.knot_layer_api_t {
		// Wrapping the inline trampoline function
		return C._layer()
	}

See the CGO_ for more information about type conversions and interoperability between the C/Go.

Configuring modules
-------------------

There is a callback ``X_config()`` but it's NOOP for now, as the configuration is not yet implemented.

Exposing module properties
--------------------------

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
		namedb_t *cache = engine->resolver.cache;

		/* Open read transaction */
		namedb_txn_t txn;
		int ret = kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY);
		if (ret != 0) {
			return NULL;
		}

		/* Read item count */
		char *result = NULL;
		const namedb_api_t *api = kr_cache_storage();
		asprintf(&result, "{ \"result\": %d }", api->count(&txn));
		kr_cache_txn_abort(&txn);
		
		return result;
	}

	struct kr_prop *cache_props(void)
	{
		static struct kr_prop prop_list[] = {
			/* Callback,   Name,   Description */
			{&get_size, "size", "Return number of records."},
			{NULL, NULL, NULL}
		};
		return prop_list;
	}

	KR_MODULE_EXPORT(cache)

Once you load the module, you can call the module property from the interactive console:

.. code-block:: bash

	$ kresolved
	...
	[system] started in interactive mode, type 'help()'
	> modules.load('cached')
	> return cached.size()
	{ "size": 53 }

*Note* |---| this relies on function pointers, so the same ``static inline`` trick as for the ``Layer()`` is required for C/Go.

.. _`processing API`: https://gitlab.labs.nic.cz/labs/knot/tree/master/src/libknot/processing
.. _`not present in Go`: http://blog.golang.org/gos-declaration-syntax
.. _CGO: http://golang.org/cmd/cgo/
.. _GCCGO: https://golang.org/doc/install/gccgo

.. |---| unicode:: U+02014 .. em dash
