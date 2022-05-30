.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-renumber:

IP address renumbering
======================

The module renumbers addresses in answers to different address space.
e.g. you can redirect malicious addresses to a blackhole, or use private address ranges
in local zones, that will be remapped to real addresses by the resolver.


.. warning:: While requests are still validated using DNSSEC, the signatures
   are stripped from final answer. The reason is that the address synthesis
   breaks signatures. You can see whether an answer was valid or not based on
   the AD flag.

.. warning:: The module is currently limited to rewriting complete octets of
   the IP addresses, i.e. only /8, /16, /24 etc. network masks are supported.

Example configuration
---------------------

.. code-block:: lua

	modules = {
		renumber = {
			-- Source subnet, destination subnet
			{'10.10.10.0/24', '192.168.1.0'},
			-- Remap /16 block to localhost address range
			{'166.66.0.0/16', '127.0.0.0'},
			-- Remap a /32 block to a single address
			{'2001:db8::/32', '::1!'},
		}
	}

.. TODO: renumber.name() hangs in vacuum, kind of.  No occurrences in code or docs, and probably bad UX.
