.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-startup:

*******
Startup
*******

The main way to run Knot Resolver is to use provided integration with ``systemd``.

.. code-block:: bash

   $ sudo systemctl start knot-resolver.service

See logs and status of running instance with ``systemctl status knot-resolver.service`` command.

.. warning::

    ``knot-resolver.service`` is not enabled by default, thus Knot Resolver won't start automatically after reboot.
    To start and enable service in one command use ``systemctl enable --now knot-resolver.service``

Unfortunately, for some cases (typically Docker and minimalistic systems), ``systemd`` is not available, therefore it is not possible to use ``knot-resolver.service``.
If you have this problem, look at :ref:`usage without systemd <deployment-no-systemd>` section.

.. note::

    If for some reason you need to use Knot Resolver as it was before version 6, check out :ref:`usage without the manager <advanced-no-manager>`
    Otherwise, it is recommended to stick to this chapter.

===============
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
