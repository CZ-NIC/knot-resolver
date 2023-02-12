.. SPDX-License-Identifier: GPL-3.0-or-later

.. _advanced-no-manager:

***********************************
Advanced: Usage without the manager
***********************************

If you want to continue using Knot Resolver as before version ``6.0.0`` this is chapter for you.
For new and less experienced users, we recommend using the newer approach starting in :ref:`Getting Started <gettingstarted-intro>` chapter.

There are a few downsides to using the legacy approach that need to be mentioned.

* configuration in Lua script
* manual process management


.. _advanced-no-manager-startup:

=======
Startup
=======

The legacy way to start Knot Resolver is to run single instance of its resolving daemon manualy using ``kresd@`` systemd integration.
The daemon is single thread process.

.. code-block:: bash

    $ sudo systemctl start kresd@1.service

.. tip::

    For more information about ``systemd`` integration see ``man kresd.systemd``.


.. _advanced-no-manager-config:

=============
Configuration
=============

Legacy way to configure Knot Resolver is to paste your Lua code typically into ``/etc/knot-resolver/kresd.conf`` configuration script.
The resolver's daemon is preconfigure to load this script when using ``kresd@`` systemd integration.

.. note::

    The configuration language is in fact Lua script, so you can use full power
    of this programming language. See article
    `Learn Lua in 15 minutes <http://tylerneylon.com/a/learn-lua/>`_ for a syntax overview.

The first thing you need to configure are the network interfaces to listen to.

The following example instructs the resolver to receive standard unencrypted DNS queries on IP addresses ``192.0.2.1`` and ``2001:db8::1``.
Encrypted DNS queries are accepted using DNS-over-TLS protocol on all IP addresses configured on network interface ``eth0``, TCP port ``853``.

.. code-block:: lua

    -- unencrypted DNS on port 53 is default
    net.listen('192.0.2.1')
    net.listen('2001:db8::1')

    net.listen(net.eth0, 853, { kind = 'tls' })


Complete configurations files examples can be found `here <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).

.. note::

    When copy&pasting examples please pay close
    attention to brackets and also line ordering - order of lines matters.