.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-config:

*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

Since version **6.0.0**, Knot Resolver uses new declarative configuration. Easiest way to configure the resolver is to paste your configuration into YAML file ``/etc/knot-resolver/config.yml``.
You can start with :ref:`network interfaces <usecase-network-interfaces>`, continue with other :ref:`common use cases <usecases-chapter>` and then look in the complete :ref:`configuration <configuration-chapter>` documentation.

Complete configurations files for examples can be found `here <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).

.. tip::

    An easy way to see the complete configuration structure is to look at the `JSON Schema <https://json-schema.org/>`_ on `http://localhost:5000/schema/ui <http://localhost:5000/schema/ui>`_ with the Knot Resolver running.
    The raw schema is availiable on `http://localhost:5000/schema <http://localhost:5000/schema>`_.

============
kresctl tool
============

========
HTTP API
========

You can use HTTP API to configure already running Knot Resolver.
By default HTTP API is configured as UNIX domain socket ``manager.sock`` located in the resolver's rundir.
This socket is used by ``kresctl`` tool.

Configuration of API can be changed only in ``/etc/knot-resolver/config.yml`` file:

.. code-block:: yaml

    management:
        interface: 127.0.0.1@5000
        # or use unix socket instead of inteface
        # unix-socket: /my/new/socket.sock

Configuration API is available on ``/config`` HTTP endpoint.
All requests support ``If-Match`` HTTP header with an ETag.
If the ETag is wrong, the request fails.

API support following HTTP request methods:

=============================   =========================
HTTP request methods            Operation
=============================   =========================
**GET**    ``/config[/path]``   returns current config with an ETag
**POST**   ``/config[/path]``   upsert (try update, if does not exists, insert), appends to array
**PUT**    ``/config[/path]``   insert (fails if object already exists)
**PATCH**  ``/config[/path]``   update (fails if object does not exist)
**DELETE** ``/config[/path]``   delete an existing object
=============================   =========================

.. note::

    Some configuration options cannot be configured via the API for stability and security reasons(e.g. API configuration itself).
    In the case of an attempt to configure such an option, the operation is rejected.

Path
----

The configuration path is used to determine specific configuration option or subtree of configuration.

Items in lists and dictionaries are reachable as follows and can also be combined:

* ``/list-name/{num-id}``
* ``/dict-name/{key}``

For example, the configuration path might look like this:

* ``/config/network/listen/1/interface``

Payload
-------

The API uses JSON encoding for payload. It has the same structure as YAML configuration file.

========================
Legacy Lua configuration
========================

Legacy way to configure Knot Resolver daemon is to paste your configuration into configuration file ``/etc/knot-resolver/kresd.conf``.
When using this configuration approach, the daemon must be started using legacy systemd service ``kresd@``.

.. note::

    When copy&pasting examples from this manual please pay close
    attention to brackets and also line ordering - order of lines matters.

    The configuration language is in fact Lua script, so you can use full power
    of this programming language. See article
    `Learn Lua in 15 minutes <http://tylerneylon.com/a/learn-lua/>`_ for a syntax overview.
