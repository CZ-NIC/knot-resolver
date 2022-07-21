.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-startup:

*******
Startup
*******

The simplest way to run Knot Resolver is to use provided Knot Resolver's systemd integration:

.. code-block:: bash

   $ sudo systemctl start knot-resolver.service

See logs and status of running instance with ``systemctl status knot-resolver.service`` command. For more information about systemd integration see ``man knot-resolver.systemd``.

.. warning::

    ``knot-resolver.service`` is not enabled by default, thus Knot Resolver won't start automatically after reboot.
    To start and enable service in one command use ``systemctl enable --now knot-resolver.service``

Legacy daemon startup
=====================

Legacy way to run single instance of Knot Resolver daemon is to use ``kresd@`` systemd integration:

.. code-block:: bash

   $ sudo systemctl start kresd@1.service

First DNS query
===============
After installation and first startup, Knot Resolver's default configuration accepts queries on loopback interface. This allows you to test that the installation and service startup were successful before continuing with configuration.

For instance, you can use DNS lookup utility ``kdig`` to send DNS queries. The ``kdig`` command is provided by following packages:

============   =================
Distribution   package with kdig
============   =================
Arch           knot
CentOS         knot-utils
Debian         knot-dnsutils
Fedora         knot-utils
OpenSUSE       knot-utils
Ubuntu         knot-dnsutils
============   =================

The following query should return list of Root Name Servers:

.. code-block:: bash

    $ kdig +short @localhost . NS
    a.root-servers.net.
    ...
    m.root-servers.net.
