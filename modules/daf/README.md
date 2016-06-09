.. _mod-daf:

DNS Application Firewall
------------------------

This module is a high-level interface for other powerful filtering modules and DNS views. It provides an easy interface to apply and monitor DNS filtering rules and a persistent memory for them. It also provides a restful service interface and an HTTP interface.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	modules = { 'http', 'daf' }

	-- Let's write some daft rules!
	
	-- Block all queries with QNAME = example.com
	daf.add 'qname = example.com deny'

	-- Filters can be combined using AND/OR...
	-- Block all queries with QNAME match regex and coming from given subnet
	daf.add 'qname ~ %w+.example.com AND src = 192.0.2.0/24 deny'

	-- We also can reroute addresses in response to alternate target
	-- This reroutes 1.2.3.4 to localhost
	daf.add 'src = 127.0.0.0/8 reroute 192.0.2.1-127.0.0.1'

	-- Subnets work too, this reroutes a whole subnet
	-- e.g. 192.0.2.55 to 127.0.0.55
	daf.add 'src = 127.0.0.0/8 reroute 192.0.2.0/24-127.0.0.0'

	-- This rewrites all A answers for 'example.com' from
	-- whatever the original address was to 127.0.0.2
	daf.add 'src = 127.0.0.0/8 rewrite example.com A 127.0.0.2'
