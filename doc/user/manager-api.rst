.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-api:

********
HTTP API
********

The Knot Resolver Manager exposes a HTTP API, through which it can be manipulated during runtime.
The API provides numerous operations, ranging from metrics collection, through cache clearance, to Resolver reconfiguration.
See the :ref:`overview <manager-api-overview>` section below.

You can use HTTP API to dynamically change configuration of already running Knot Resolver.
By default the API is configured as UNIX domain socket located in the resolver's rundir ``/run/knot-resolver/kres-api.sock``.
This socket is used by ``kresctl`` utility in default.

What can the API do?
--------------------

This HTTP API is intended for development of custom tooling to interface with the Manager in an automated way.
If you do not intend to develop any such tools, see the :ref:`kresctl utility <manager-client>`.
It uses this HTTP API and provides a convenient command line interface for daily use.

Configuring the API socket
--------------------------

The HTTP API may be configured to listen on different addresses or even a UNIX-style socket through the ``management`` configuration subtree.
The subtree can only be modified in the configuration YAML file, i.e. it may not be changed using the API itself.

.. code-block:: yaml

    management:
        interface: 127.0.0.1@5000
        # or use a unix socket instead of inteface
        # unix-socket: /my/new/socket.sock


.. warning::

   The API does not provide authentication nor authorization of any sort.
   As the API is powerful enough to completely change the behaviour of your resolver, you should only ever expose it to localhost or a trusted and tightly controlled network, so that no malicious actors may access it.

   Should you require any sort of remote control, please consider using an existing VPN solution, or an authenticating HTTPS proxy as a layer on top of the management API.


.. _manager-api-overview:

Overview
--------

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

- ``POST /cache/clear`` purges cache records matching the specified criteria, see :ref:`manager-api-cache-clear`



.. _manager-api-config:

Configuration API
-----------------

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


**``path``:**
    Determines the specific configuration option or configuration subtree on that path.
    Items in lists and dictionaries are reachable using indices ``/list-name/{index}/`` and keys ``/dict-name/{key}/``.

    The API can operate on any configuration subtree by specifying a `JSON pointer <https://www.rfc-editor.org/rfc/rfc6901>`_ in the URL path (property names and list indices joined with ``/``). For example, to get the number of worker processes, you can send a ``GET`` request to ``v1/config/workers``.

**Request body format:**
    The API by default expects a JSON-formatted message, but it can also parse YAML when the ``Content-Type`` header is set to ``application/yaml`` or ``text/vnd.yaml``. The return value is always a JSON with ``Content-Type: application/json``. The schema of input and output is always a subtree of the configuration data model which is described by the JSON schema exposed at ``GET /schema``.

**API versioning:**
    The ``v1`` version qualifier is there for future-proofing. We don't have plans to change the API any time soon, but if it does happen, we will support both API versions for some transition period.

**ETag:**
    To prevent race conditions when changing configuration from multiple clients simultaneously, every response from the Manager has an ``ETag`` header set. Requests can then provide ``If-Match`` and ``If-None-Match`` headers with the latest ``ETag`` value, and the corresponding request processing fails with HTTP error code 412 (precondition failed) if there are conflicting changes.

Some configuration options cannot be changed dynamically through the API for stability or security reasons (e.g. the ``management`` subtree).
These options are explicitly documented as such. Any requests to change them through the API will be rejected.


.. _manager-api-cache-clear:

Cache clearing API
------------------

``POST /cache/clear`` purges cache records matching the specified criteria.
Some general properties of cache-clearance are also described at :ref:`config-cache-clear`.

Parameters
``````````
Parameters are in JSON and sent with the HTTP request as its body.

.. option:: "name": "<name>"

   Optional, subtree to purge; if the name isn't provided, the whole cache is purged (and any other parameters are disregarded).

.. option:: "exact-name": true|false

   :default: false

   If set to ``true``, only records with *the same* name are removed.

.. option:: "rr-type": "<rr_type>"

   Optional, the specific DNS resource record type to remove.

   Only supported with :option:`exact-name <"exact-name": true|false>` enabled.

.. option:: "chunk-size": integer

   :default: 100

   The number of records to remove in a single round. The purpose is not to block the resolver for too long.
   By default, the resolver repeats the command after at least one millisecond until all the matching data is cleared.

Return value
````````````

The return value is an object that always contains (at least) the count field.

.. option:: "count": integer

   The number of items removed from the cache by this call (may be 0 if no entry matched criteria).

   Always present.

.. option:: "not_apex": true|false

   Cleared subtree is not cached as zone apex; proofs of non-existence were probably not removed.

   Optional. Considered ``false`` when not present.

.. option:: "subtree": "<zone_apex>"

   Hint where zone apex lies (this is an estimation based on the cache contents and may not always be accurate).

   Optional.

.. option:: "chunk_limit": true|false

   More than :option:`chunk-size <"chunk-size": <integer>>` items needs to be cleared, clearing will continue asynchronously.

   Optional. Considered ``false`` when not present.
