.. _mod-cookiectl:

DNS Cookies
-----------

The module is used for configuring the :rfc:`7873` DNS cookies functionality behaviour.

Example Configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Load the module.
	modules = { 'cookiectl' }

	-- Configure the client part of the resolver. Set 8 bytes of the client
	-- secret and choose the hashing algorithm to be used.
	cookiectl.config( { ['client_secret'] = { 0, 1, 2, 3, 4, 5, 6, 7 },
	                    ['client_cookie_alg'] = 'FNV-64' } )

	-- Configure the server part of the resolver. Sets a string to be used
	-- as server secret. Also chooses the hashing algorithm to be used.
	cookiectl.config( { ['server_secret'] = 'secret key',
	                    ['server_cookie_alg'] = 'FNV-64' } )

	-- Enable client cookie functionality. (Add cookies into outbound
	-- queries.)
	cookiectl.config( { ['client_enabled'] = true } )

	-- Enable server cookie functionliaty. (Handle cookies in inbound
	-- requests.)
	cookiectl.config( { ['server_enabled'] = true } )

.. tip:: If you want to change several parameters regarding the client or server configuration then do it within a single ``cookiectl.config()`` invocation.

Properties
^^^^^^^^^^

.. function:: cookiectl.config(configuration)

  :param table configuration: part of cookie configuration to be changed, may be called without parameter
  :return: JSON dictionary containing corrent configuration

  The function may be called without any parameter. In such case it only returns current configuration. The returned JSON alsao contains available algorithm choices.

Dependencies
^^^^^^^^^^^^

* `Nettle <https://www.lysator.liu.se/~nisse/nettle/>`_ required for HMAC-SHA256
* `dns-cookies-wip branch of libknot <https://gitlab.labs.nic.cz/labs/knot/tree/dns-cookies-wip>`_ for DNS cookies handling

.. warning:: Libknot is dropping its processing API in latest development versions. However, this should not be a big deal as only some structures have been in usage by the resolver code.
