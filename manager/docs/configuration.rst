*************************
Declarative configuration
*************************

.. contents::
    :depth: 2
    :local:

Final documentation will be generated from configuration datamodel.
This is just a raw proposal.

server
======

.. envvar:: server:hostname: <str>

    Detailed information probably from python docstring.

network
=======

.. envvar:: network:interfaces: <list>

    .. envvar:: listen: <ip-address>[@port]

    .. envvar:: kind: <dns|xdp|dot|doh|control>

        :default: dns

    .. envvar:: freebind: <bool>

        :default: false

    Example:

    .. code-block:: yaml

        network:
            interfaces:
              - listen: eth0@53




