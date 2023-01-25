.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-install:

************************
Installation and Startup
************************

As a first step, configure your system to use upstream repositories which have
the **latest version** of Knot Resolver. Follow the instructions below for your
distribution.

.. note:: Please note that the packages available in distribution repositories of Debian and Ubuntu are outdated. Make sure to follow these steps to use our upstream repositories.

.. tabs::

    .. code-tab:: bash Debian/Ubuntu

        $ wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
        $ sudo dpkg -i knot-resolver-release.deb
        $ sudo apt update
        $ sudo apt install -y knot-resolver

    .. code-tab:: bash CentOS 7+

        $ sudo yum install -y epel-release
        $ sudo yum install -y knot-resolver

    .. code-tab:: bash Fedora

        $ sudo dnf install -y knot-resolver

    .. code-tab:: bash Arch Linux

        $ sudo pacman -S knot-resolver

**openSUSE Leap/Tumbleweed**

Add the `OBS <https://en.opensuse.org/Portal:Build_Service>`_ package repository `home:CZ-NIC:knot-resolver-latest <https://software.opensuse.org/download.html?project=home%3ACZ-NIC%3Aknot-resolver-latest&package=knot-resolver>`_ to your system.

.. note::

    If for some reason you need to **install Knot Resolver from source**, check out :ref:`building from sources <build>` documentation for developers.