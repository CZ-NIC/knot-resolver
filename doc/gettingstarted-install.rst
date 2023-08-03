.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-install:

************
Installation
************

Some Linux distributions contain Knot Resolver in their official repositories,
but their policies usually don't allow keeping it up to date.
Therefore we recommend to use upstream repositories which have the **latest stable version** of Knot Resolver.

Please, follow the instructions for your packaging system:

.. tabs::

    .. tab:: Debian

        Please follow https://pkg.labs.nic.cz/doc/?project=knot-resolver

    .. tab:: Ubuntu

        .. code:: bash

            sudo apt install software-properties-common
            sudo add-apt-repository ppa:cz.nic-labs/knot-resolver
            sudo apt update
            sudo apt install knot-resolver6

        For details see
        https://launchpad.net/~cz.nic-labs/+archive/ubuntu/knot-resolver

    .. tab:: .rpm

        Please follow https://copr.fedorainfracloud.org/coprs/g/cznic/knot-resolver/

    .. tab:: Docker

        .. code:: bash

            sudo docker run -ti --net=host docker.io/cznic/knot-resolver:6

        Hub page: https://hub.docker.com/r/cznic/knot-resolver



If for some reason you need to install Knot Resolver **from source**, check out :ref:`building from sources <build>` documentation for developers.
