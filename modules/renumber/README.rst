.. _mod-renumber:

Renumber
--------

The module allows you to remap addresses in answers to different address spaces.
You can for example redirect malicious addresses to a blackhole, or use private address ranges
in local zones that will be remapped to real addresses by the resolver.


.. warning:: The requests is still validated using DNSSEC, but the signatures are stripped from the final answer. The reason is that the address synthesis breaks signatures. You can see whether the answer was valid or not based on the AD flag presence.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	modules = {
		renumber = {
			-- Source subnet, destination subnet
			{'10.10.10.0/24', '192.168.1.0'},
			-- Remap /16 block to localhost address range
			{'166.66.0.0/16', '127.0.0.0'}
		}
	}
