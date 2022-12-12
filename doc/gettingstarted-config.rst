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

    An easy way to see the complete configuration structure is to look at the `JSON Schema <https://json-schema.org/>`_ of the configuration format with some graphical visualizer such as `this one <https://json-schema.app/>`_.
    The raw schema is accessible from every running Knot Resolver at the HTTP API socket at path ``/schema`` or on `this link <_static/config-schema.json>`_ (valid only for the version of resolver this documentation was generated for)

===================
Management HTTP API
===================

You can use HTTP API to dynamically change configuration of already running Knot Resolver.
By default the API is configured as UNIX domain socket ``manager.sock`` located in the resolver's rundir (typically ``/run/knot-resolver/``).
This socket is used by ``kresctl`` utility in default.

The API setting can be changed only in ``/etc/knot-resolver/config.yml`` configuration file:

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


===============
kresctl utility
===============

Command-line utility to configure and control running Knot Resolver. It uses the above mentioned HTTP API.
With no changed configuration for management HTTP API, ``kresctl`` shoul work out of the box.
In other case there is ``-s`` argument to specify path to HTTP API endpoint.

.. code-block::

    $ kresctl -h
    usage: kresctl [-h] [-i] [-s SOCKET] {stop,config,exit} ...

    Command-line interface for controlling Knot Resolver

    positional arguments:
    {stop,config,exit}    command type
        stop                shutdown everything
        config              dynamically change configuration of a running resolver
        exit                exit kresctl

    optional arguments:
    -h, --help            show this help message and exit
    -i, --interactive     Interactive mode of kresctl utility
    -s SOCKET, --socket SOCKET
                          Path to the Unix domain socket of the configuration API


You can also get detailed help of every command, e.g. ``$ kresctl config -h``.

Folowing command changes configuration of the number of daemon workers to 4.

.. code-block::

    $ kresctl config /workers 4


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
