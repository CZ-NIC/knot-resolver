.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-renumber:

IP address renumbering
======================

Addresses renumbering in answers to different address space.
e.g. you can redirect malicious addresses to a blackhole, or use private address ranges
in local zones, that will be remapped to real addresses by the resolver.

.. warning::

   While requests are still validated using DNSSEC, the signatures
   are stripped from final answer. The reason is that the address synthesis
   breaks signatures. You can see whether an answer was valid or not based on
   the AD flag.

Example configuration
---------------------

.. code-block:: yaml

   network:
     address-renumbering:
       - source: 10.10.10.0/24
         destination: 192.168.1.0
       # remap /16 block to localhost address range
       - source: 166.66.0.0/16
         destination: 127.0.0.0
       # remap /26 subnet (64 ip addresses)
       - source: 166.55.77.128/26
         destination: 127.0.0.192
       # remap a /32 block to a single address
       - source: 2001:db8::/32
         destination: '::1!'
