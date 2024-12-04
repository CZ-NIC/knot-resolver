.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-api:

********
HTTP API
********

===================
Management HTTP API
===================

You can use HTTP API to dynamically change configuration of already running Knot Resolver.
By default the API is configured as UNIX domain socket located in the resolver's rundir ``/run/knot-resolver/kres-api.sock``.
This socket is used by ``kresctl`` utility in default.

The API setting can be changed only in ``/etc/knot-resolver/config.yaml`` configuration file:

.. code-block:: yaml

    management:
        interface: 127.0.0.1@5000
        # or use unix socket instead of inteface
        # unix-socket: /my/new/socket.sock

First version of configuration API endpoint is available on ``/v1/config`` HTTP endpoint.
Configuration API supports following HTTP request methods:

================================   =========================
HTTP request methods               Operation
================================   =========================
**GET**    ``/v1/config[/path]``   returns current configuration with an ETag
**PUT**    ``/v1/config[/path]``   upsert (try update, if does not exists, insert), appends to array
**PATCH**  ``/v1/config[/path]``   update property using `JSON Patch <https://jsonpatch.com/>`_
**DELETE** ``/v1/config[/path]``   delete an existing property or list item at given index
================================   =========================

.. note::

    Managemnet API has other useful endpoints (metrics, schema, ...), see the detailed :ref:`API documentation <manager-api>`.

**path:**
    Determines specific configuration option or configuration subtree on that path.
    Items in lists and dictionaries are reachable using indexes ``/list-name/{index}/`` and keys ``/dict-name/{key}/``.

**payload:**
    JSON or YAML encoding is used for configuration payload.

.. note::

    Some configuration options cannot be configured via the API for stability and security reasons(e.g. API configuration itself).
    In the case of an attempt to configure such an option, the operation is rejected.


-----------------------------------




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
- ``GET /metrics`` returns 301 (Moved Permanently) and redirects to ``/metrics/json``
- ``GET /metrics/json`` provides aggregated metrics in JSON format 
- ``GET /metrics/prometheus`` provides metrics in Prometheus format
    The ``prometheus-client`` Python package needs to be installed. If not installed, it returns 404 (Not Found).
- ``GET /`` static response that could be used to determine, whether the Manager is running
- ``POST /stop`` gracefully stops the Manager, empty request body
- ``POST /cache/clear`` purges cache records matching the specified criteria, see :ref:`cache clearing <config-cache-clear>`
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
- ``PATCH`` updates the configuration using `JSON Patch <https://jsonpatch.com/>`_

To prevent race conditions when changing configuration from multiple clients simultaneously, every response from the Manager has an ``ETag`` header set. Requests then accept ``If-Match`` and ``If-None-Match`` headers with the latest ``ETag`` value and the corresponding request processing fails with HTTP error code 412 (precondition failed).

