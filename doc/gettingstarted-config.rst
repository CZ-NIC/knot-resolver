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

============================
Configuration tool - kresctl
============================

=================
Configuration API
=================

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
    `Learn Lua in 15 minutes`_ for a syntax overview.

.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
