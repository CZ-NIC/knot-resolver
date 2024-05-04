.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-api:

********
HTTP API
********

See also the :ref:`kresctl utility <manager-client>`.  It uses this HTTP API and provides a convenient command line interface.

You can use HTTP API to dynamically change configuration of already running Knot Resolver.
By default the API is configured as UNIX domain socket located in the resolver's rundir ``/run/knot-resolver/kres-api.sock``.
This socket is used by ``kresctl`` utility in default.

What can the API do?
--------------------

- ``GET /`` static response that could be used to determine, whether the Manager is running
- ``POST /stop`` gracefully stops the Manager, empty request body

- ``{GET,PUT,DELETE,PATCH} /v1/config`` reads or modifies the current configuration.  See :ref:`manager-api-config`
- ``POST /reload`` reloads the configuration file.
  Both these methods of dynamic reconfiguration are equivalent in terms of their capabilities.
- ``GET /schema`` returns JSON schema of the configuration data model
- ``GET /schema/ui`` redirect to an external website with the JSON schema visualization

- ``GET /metrics`` returns 301 (Moved Permanently) and redirects to ``/metrics/json``
- ``GET /metrics/json`` provides aggregated metrics in JSON format
- ``GET /metrics/prometheus`` provides metrics in Prometheus format
    The ``prometheus-client`` Python package needs to be installed. If not installed, it returns 404 (Not Found).

- ``POST /cache/clear`` purges cache records matching the specified criteria, see :ref:`cache clearing <config-cache-clear>`


Configuring the API socket
--------------------------

The API setting can be changed only in ``/etc/knot-resolver/config.yaml`` configuration file:

.. code-block:: yaml

    management:
        interface: 127.0.0.1@5000
        # or use unix socket instead of inteface
        # unix-socket: /my/new/socket.sock


.. _manager-api-config:

The configuration API
---------------------

You can use HTTP API to read or dynamically change the configuration of a running Knot Resolver.
Configuration API supports the following HTTP request methods:

================================   =========================
HTTP request methods               Operation
================================   =========================
**GET**    ``/v1/config[/path]``   return a subtree of the current configuration with an ETag
**PUT**    ``/v1/config[/path]``   upsert (try update, if does not exists, insert), appends to array
**PATCH**  ``/v1/config[/path]``   update property using `JSON Patch <https://jsonpatch.com/>`_
**DELETE** ``/v1/config[/path]``   delete an existing property or list item at given index
================================   =========================


**path:**
    Determines specific configuration option or configuration subtree on that path.
    Items in lists and dictionaries are reachable using indexes ``/list-name/{index}/`` and keys ``/dict-name/{key}/``.

    The API can operate on any configuration subtree by specifying a `JSON pointer <https://www.rfc-editor.org/rfc/rfc6901>`_ in the URL path (property names and list indices joined with ``/``). For example, to get the number of worker processes, you can send ``GET`` request to ``v1/config/workers``.

**payload:**
    The API by default expects JSON, but it can also parse YAML when the ``Content-Type`` header is set to ``application/yaml`` or ``text/vnd.yaml``. The return value is always a JSON with ``Content-Type: application/json``. The schema of input and output is always a subtree of the configuration data model which is described by the JSON schema exposed at ``/schema``.

**API versioning:**
    The ``v1`` version qualifier is there for future-proofing. We don't have any plans at the moment to change the API any time soon. If that happens, we will support both old and new API versions for the some transition period.

**ETag:**
    To prevent race conditions when changing configuration from multiple clients simultaneously, every response from the Manager has an ``ETag`` header set. Requests then accept ``If-Match`` and ``If-None-Match`` headers with the latest ``ETag`` value and the corresponding request processing fails with HTTP error code 412 (precondition failed).

Some configuration options cannot be changed dynamically for stability or security reasons (e.g. API configuration itself).
In the case of an attempt to configure such an option, the operation is rejected.


