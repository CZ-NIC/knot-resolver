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

    .. tab:: Debian/Ubuntu

        Please follow https://pkg.labs.nic.cz/doc/?project=knot-resolver

    .. tab:: .rpm

        Please follow https://copr.fedorainfracloud.org/coprs/g/cznic/knot-resolver/

    .. tab:: Docker

        DockerHub page: https://hub.docker.com/r/cznic/knot-resolver

        .. code:: bash

            sudo docker run --rm -ti --network host docker.io/cznic/knot-resolver

        More about Docker deployments can be found in :ref:`deployment-docker` section.

If for some reason you need to install Knot Resolver **from sources**,
check out `building from sources <./dev/build.html>`_ section in developer documentation.
