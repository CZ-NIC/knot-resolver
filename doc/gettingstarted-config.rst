.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-config:

*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

Easiest way to configure Knot Resolver is to put configuration to ``/etc/knot-resolver/config.yml`` file.

The first thing you will probably want to configure are the network interfaces to listen to.

The following example instructs the resolver to receive standard unencrypted DNS queries on ``192.0.2.1`` and ``2001:db8::1`` IP addresses.
Encrypted DNS queries using ``DNS-over-TLS`` protocol are accepted on all IP addresses of ``eth0`` network interface, TCP port ``853``.
For more details look at the :ref:`network configuration <config-network>`.

.. code-block:: yaml

    network:
        listen:
        - interface: ['192.0.2.1', '2001:db8::1'] # port 53 is default
        - interface: 'eth0'
            port: 853
            kind: 'dot' # DNS-over-TLS

You can also start exploring the configuration by reading about :ref:`common use cases <usecases-chapter>` or look at the complete :ref:`configuration <configuration-chapter>` documentation.

Complete configurations files examples can be found `here <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
Examples are also installed as documentation files, typically in ``/usr/share/doc/knot-resolver/examples/`` directory (location may be different based on your Linux distribution).

.. tip::

    An easy way to see the complete configuration structure is to look at the `JSON Schema <https://json-schema.org/>`_ of the configuration format with some graphical visualizer such as `this one <https://json-schema.app/>`_.
    The raw schema is accessible from every running Knot Resolver at the HTTP API socket at path ``/schema`` or on `this link <_static/config.schema.json>`_ (valid only for the version of resolver this documentation was generated for)


==========
Validation
==========

Knot Resolver's configuration follows strict schema for validation.

You can use :ref:` kresctl <manager-client>` utility to validate your configuration before pushing it into the running resolver.
It should help prevent many typos in the configuration.

.. code-block::

    $ kresctl validate /etc/knot-resolver/config.yml


======
Reload
======

If you change the configuration while the resolver is running, you can push it into the running resolver by invoking a ``systemd`` reload command.

.. code-block::

    # systemctl reload knot-resolver.service

.. note::

    **Reloading configuration** can fail even when your configuration is valid, because some options cannot be changed while running. You can always find an explanation of the error in the log accesed by the ``journalctl -eu knot-resolver`` command.


==============
Management API
==============

The configuration can be also changed at runtime through the provided :ref:`management API <manager-api>`.
Changing the configuration through the API does not introduce any downtime to the provided service.

.. note::

    Any changes made during runtime are not persistent unless you modify the configuration file yourself.

The API can be used from the command-line with the :ref:`kresctl <manager-client>` utility.
For example, you can change the number of daemon workers.

.. code-block::

    $ kresctl config --set /workers 4
