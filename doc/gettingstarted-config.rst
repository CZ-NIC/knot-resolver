.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-config:

*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

Easiest way to configure the resolver is to have your configuration in the ``/etc/knot-resolver/config.yml`` YAML file. If you change the configuration while the resolver is running, you can load it into the running resolver by invoking the ``systemctl reload knot-resolver.service`` command.

.. note::

    **Reloading configuration** can fail even when your configuration is valid, because some options cannot be changed while running. You can always find an explanation of the error in the log accesed by the ``journalctl -eu knot-resolver`` command.


The configuration file follows a strict schema which can be validated using ``kresctl validate /path/to/config/file`` without running the resolver.

You can continue exploring the configuration options by reading about :ref:`network interfaces <usecase-network-interfaces>`, continue with other :ref:`common use cases <usecases-chapter>` or look at the complete :ref:`configuration <configuration-chapter>` documentation.

Complete configurations files for examples can be found `here <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).

.. tip::

    An easy way to see the complete configuration structure is to look at the `JSON Schema <https://json-schema.org/>`_ of the configuration format with some graphical visualizer such as `this one <https://json-schema.app/>`_.
    The raw schema is accessible from every running Knot Resolver at the HTTP API socket at path ``/schema`` or on `this link <_static/config.schema.json>`_ (valid only for the version of resolver this documentation was generated for)


==========
Config API
==========

Configuration of the resolver can be changed at runtime through the provided :ref:`HTTP API <manager-api>`. Any changes made during runtime are not persistent unless you modify the configuration file yourself. Also, changing the configuration through the API does not introduce any downtime to the provided service.

The API can be used from the command-line with the :ref:`kresctl utility <manager-kresctl>`.


=================
Lua configuration
=================

When reading the documentation, whenever you see a configuration snippet, you might see a Lua version of the configuration as well. Lua was used earlier as the main configuration language. Starting with Knot Resolver version 6.0.0 it was replaced by the YAML configuration we wrote about in all sections above. Lua will remain supported and in use internally, however unless want to do something really advanced, you should ignore it and use the YAML configuration. You can learn more about the Lua configuration in :ref:`this section <config-lua>`.