.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-config:

*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

Easiest way to configure Knot Resolver is to paste your configuration into YAML file ``/etc/knot-resolver/config.yml``.
Complete configurations files for examples can be found `here <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).

==============================
Lua configuration in YAML file
==============================


========================
Lua legacy configuration
========================

Legacy way to configure Knot Resolver daemon is to paste your configuration into configuration file ``/etc/knot-resolver/kresd.conf``.
When using this configuration approach, the daemon must be started using legacy systemd service ``kresd@``.

.. note::

    When copy&pasting examples from this manual please pay close
    attention to brackets and also line ordering - order of lines matters.

    The configuration language is in fact Lua script, so you can use full power
    of this programming language. See article
    `Learn Lua in 15 minutes`_ for a syntax overview.

===============================
Listening on network interfaces
===============================

The following configuration instructs Knot Resolver to receive standard unencrypted DNS queries on IP addresses `192.0.2.1` and `2001:db8::1`.
Encrypted DNS queries are accepted using DNS-over-TLS protocol on all IP addresses configured on network interface `eth0`, TCP port 853.

.. tabs::

    .. group-tab:: |yaml|

        .. code-block:: yaml

            network:
              listen:
                - interface: ['192.0.2.1', '2001:db8::1'] # unencrypted DNS on port 53 is default
                - interface: 'eth0'
                  port: 853
                  kind: 'dot'

    .. group-tab:: |lua|

        Network interfaces to listen on and supported protocols are configured using :func:`net.listen()` function.

        .. code-block:: lua

            -- unencrypted DNS on port 53 is default
            net.listen('192.0.2.1')
            net.listen('2001:db8::1')
            net.listen(net.eth0, 853, { kind = 'tls' })

.. warning::

    On machines with multiple IP addresses on the same interface avoid listening on wildcards ``0.0.0.0`` or ``::``.
    Knot Resolver could answer from different IP addresses if the network address ranges
    overlap, and clients would refuse such a response.

.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
