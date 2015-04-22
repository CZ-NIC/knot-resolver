*************************
Knot DNS Resolver library
*************************

Requirements
============

* libknot_ 2.0 (Knot DNS high-performance DNS library.)

Library layout
==============

.. contents::
   :depth: 1
   :local:

The library as described provides basic services for name resolution, which should cover the usage.

Resolving a name
----------------

.. note:: Migrating from ``getaddrinfo``

Using getdns API
----------------

.. note:: These are not the droids you're looking for, move along.

.. _lib-layers:

Writing layers
==============

The resolver :ref:`library <lib_index>` leverages the `processing API`_ from the libknot to separate packet processing code
into layers. In order to keep the core library sane and coverable, there are only two built-in layers:
the :c:func:`iterate_layer`, and the :c:func:`itercache_layer`.

*Note* |---| This is only crash-course in the library internals, see the resolver :ref:`library <lib_index>` documentation for the complete overview of the services.

The library offers following services:

- :ref:`Cache <lib_api_cache>` - MVCC cache interface for retrieving/storing resource records.
- :ref:`Resolution plan <lib_api_rplan>` - Query resolution plan, a list of partial queries (with hierarchy) sent in order to satisfy original query. This contains information about the queries, nameserver choice, timing information, answer and its class.
- :ref:`Nameservers <lib_api_nameservers>` - Reputation database of nameservers, this serves as an aid for nameserver choice.

A processing layer is going to be called by the query resolution driver for each query,
so you're going to work with :ref:`struct kr_request <lib_api_rplan>` as your per-query context. This structure contains pointers to
resolution context, resolution plan and also the final answer. You're likely to retrieve currently solved query from the query plan:

.. code-block:: c

	int consume(knot_layer_t *ctx, knot_pkt_t *pkt)
	{
		struct kr_request *request = ctx->data;
		struct kr_query *query = kr_rplan_current(request->rplan);
	}

This is only passive processing of the incoming answer. If you want to change the course of resolution, say satisfy a query from a local cache before the library issues a query to the nameserver, you can use states (see the :ref:`Static hints <mod-hints>` for example).

.. code-block:: c

	int produce(knot_layer_t *ctx, knot_pkt_t *pkt)
	{
		struct kr_request *request = ctx->data;
		struct kr_query *cur = kr_rplan_current(request->rplan);
		
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
		struct kr_request *request = ctx->data;
		struct kr_rplan *rplan = request->rplan;

		/* Print the query sequence with start time. */
		char qname_str[KNOT_DNAME_MAXLEN];
		struct kr_query *qry = NULL
		WALK_LIST(qry, rplan->resolved) {
			knot_dname_to_str(qname_str, qry->sname, sizeof(qname_str));
			printf("%s at %u\n", qname_str, qry->timestamp);
		}

		return ctx->state;
	}

.. _libknot: https://gitlab.labs.nic.cz/labs/knot/tree/master/src/libknot
.. _`processing API`: https://gitlab.labs.nic.cz/labs/knot/tree/master/src/libknot/processing

.. |---| unicode:: U+02014 .. em dash
