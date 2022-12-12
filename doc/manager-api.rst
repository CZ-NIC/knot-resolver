.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-api:

********
HTTP API
********

===================================
Dynamically changing configuration
===================================

Knot Resolver Manager is capable of dynamically changing its configuration via an HTTP API or by reloading its config file. Both methods are equivalent in terms of its capabilities. The ``kresctl`` utility uses the HTTP API and provides a convinient command line interface.

Reloading configuration file
============================

To reload the configuration file, send the ``SIGHUP`` signal to the Manager process. The original configuration file will be read again, validated and in case of no errors, the changes will be applied.

Note: You can also send ``SIGHUP`` to the top-level process, to the supervisord. Normally, supervisord would stop all processes and reload its configuration when it receives SIGHUP. However, we have eliminated this footgun in order to prevent anyone from accidentally shutting down the whole resolver. Instead, the signal is only forwarded to the Manager.


HTTP API
========

Listen address
--------------

By default, the Manager exposes its HTTP API on a Unix socket at ``FIXME``. However, you can change where it listens by changing the ``management.interface`` config option. To use ``kresctl``, you have to tell it this value.


List of API endpoints
---------------------

- ``GET /schema`` returns JSON schema of the configuration data model
- ``GET /schema/ui`` redirect to an external website with the JSON schema visualization
- ``GET /metrics`` provides Prometheus metrics
- ``GET /`` static response that could be used to determine, whether the Manager is running
- ``POST /stop`` gracefully stops the Manager, empty request body
- ``{GET,PUT,DELETE,PATCH} /v1/config`` allows reading and modifying current configuration


Config modification endpoint (v1)
---------------------------------

Note: The ``v1`` version qualifier is there for future-proofing. We don't have any plans at the moment to change the API any time soon. If that happens, we will support both old and new API versions for the some transition period.

The API by default expects JSON, but can also parse YAML when the ``Content-Type`` header is set to ``application/yaml`` or ``text/vnd.yaml``. The return value is always a JSON with ``Content-Type: application/json``. The schema of input and output is always a subtree of the configuration data model which is described by the JSON schema exposed at ``/schema``.

The API can operate on any configuration subtree by specifying a `JSON pointer <https://www.rfc-editor.org/rfc/rfc6901>`_ in the URL path (property names and list indices joined with ``/``). For example, to get the number of worker processes, you can send ``GET`` request to ``v1/config/workers``.

The different HTTP methods perform different modifications of the configuration:

- ``GET`` return subtree of the current configuration
- ``PUT`` set property
- ``DELETE`` removes the given property or list item at the given index
- ``PATCH`` updates the configuration using `JSON Patch <https://jsonpatch.com/>_`

To prevent race conditions when changing configuration from multiple clients simultaneously, every response from the Manager has an ``ETag`` header set. Requests then accept ``If-Match`` and ``If-None-Match`` headers with the latest ``ETag`` value and the corresponding request processing fails with HTTP error code 412 (precondition failed).

