.. SPDX-License-Identifier: GPL-3.0-or-later

.. _usecase-network-interfaces:

*******************************
Listening on network interfaces
*******************************

The first thing you will probably need to configure are the network interfaces to listen to.

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