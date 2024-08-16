.. SPDX-License-Identifier: GPL-3.0-or-later

.. _quickstart-intro:

Welcome to Knot Resolver Quick Start Guide! This chapter will guide you through first installation and basic setup recommended for your use-case.

Before we start let us explain basic conventions used in this text:

This is Linux/Unix shell command to be executed and an output from this command:

.. code-block:: bash

    $ echo "This is output!"
    This is output!
    $ echo "We use sudo to execute commands as root:"
    We use sudo to execute commands as root:
    $ sudo id
    uid=0(root) gid=0(root) groups=0(root)

Snippets from Knot Resolver's configuration file **do not start with $ sign** and look like this:

.. code-block:: lua

    -- this is a comment
    -- following line will start listening on IP address 192.0.2.1 port 53
    net.listen('192.0.2.1')


.. _quickstart-install:

************
Installation
************

We recommend using the latest released Knot Resolver version.
Our upstream releases undergo extensive automated testing and are suitable for production.

Packages available in your distribution's may be outdated.
Follow the instructions below to obtain the latest Knot Resolver version for your distribution.


Debian / Ubuntu
---------------

Please use our `official repos <https://pkg.labs.nic.cz/doc/?project=knot-resolver>`__
for Debian and Ubuntu.
Debian unstable and testing usually contain latest Knot Resolver version.

After that ``apt`` will keep updating knot-resolver 5.x packages from our repositories.

If you used our older repo until now, you may want to also uninstall the helper package
by ``apt purge knot-resolver-release``.

Enterprise Linux 7, 8, 9
------------------------

Use Fedora EPEL.

::

   yum install -y epel-release
   yum install -y knot-resolver

Package updates are delayed by about one week after release. To obtain the
latest released version early, you can use the epel-testing repository.

::

   yum install -y --enablerepo epel-testing knot-resolver

Fedora
------

Use the distribution's repositories where we maintain up-to-date packages.

::

   dnf install -y knot-resolver

Package releases are delayed by about a week. To obtain the latest released
version early, you can use the updates-testing repository.

::

   dnf install -y --enablerepo updates-testing knot-resolver

openSUSE
--------

Just add our `COPR repository <https://copr.fedorainfracloud.org/coprs/g/cznic/knot-resolver5>`__,
based on the variant of your openSUSE:
::

  # Leap 15.5
  zypper addrepo https://copr.fedorainfracloud.org/coprs/g/cznic/knot-resolver5/repo/opensuse-leap-15.5/group_cznic-knot-resolver5-opensuse-leap-15.5.repo

  # Tumbleweed
  zypper addrepo https://copr.fedorainfracloud.org/coprs/g/cznic/knot-resolver5/repo/opensuse-tumbleweed/group_cznic-knot-resolver5-opensuse-tumbleweed.repo

Then you can install as usual with
::

   zypper install knot-resolver

Arch Linux
----------

::

   pacman -S knot-resolver


