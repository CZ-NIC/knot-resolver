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

As a first step add following repositories with the **latest version** of Knot Resolver. Please note that the packages available in distribution's repositories are often outdated, especially in Debian and Ubuntu repositories, and this guide might not work with their old versions.

**Arch Linux**

Use
`knot-resolver <https://aur.archlinux.org/packages/knot-resolver/>`_
package from AUR_.

**CentOS 7**

.. code-block:: bash

    $ sudo yum install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.el.rpm
    $ sudo yum install -y knot-resolver

**Debian/Ubuntu**

.. code-block:: bash

    $ wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
    $ sudo dpkg -i knot-resolver-release.deb
    $ sudo apt update
    $ sudo apt install -y knot-resolver

**Fedora**

.. code-block:: bash

    $ sudo dnf install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.fedora.rpm
    $ sudo dnf install -y knot-resolver

**OpenSUSE Leap / Tumbleweed**
Add the `OBS <https://en.opensuse.org/Portal:Build_Service>`_ package repository `home:CZ-NIC:knot-resolver-latest <https://software.opensuse.org/download.html?project=home%3ACZ-NIC%3Aknot-resolver-latest&package=knot-resolver>`_ to your system.

.. _AUR: https://wiki.archlinux.org/index.php/Arch_User_Repository
