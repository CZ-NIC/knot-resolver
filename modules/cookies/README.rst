.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-cookies:

DNS Cookies
===========

The module performs most of the :rfc:`7873` DNS cookies functionality. Its main purpose is to check the cookies of inbound queries and responses. It is also used to alter the behaviour of the cookie functionality.

Example Configuration
---------------------

.. code-block:: lua

	-- Load the module before the 'iterate' layer.
	modules = {
	        'cookies < iterate'
	}

	-- Configure the client part of the resolver. Set 8 bytes of the client
	-- secret and choose the hashing algorithm to be used.
	-- Use a string composed of hexadecimal digits to set the secret.
	cookies.config { client_secret = '0123456789ABCDEF',
	                 client_cookie_alg = 'FNV-64' }

	-- Configure the server part of the resolver.
	cookies.config { server_secret = 'FEDCBA9876543210',
	                  server_cookie_alg = 'FNV-64' }

	-- Enable client cookie functionality. (Add cookies into outbound
	-- queries.)
	cookies.config { client_enabled = true }

	-- Enable server cookie functionality. (Handle cookies in inbound
	-- requests.)
	cookies.config { server_enabled = true }

.. tip:: If you want to change several parameters regarding the client or server configuration then do it within a single ``cookies.config()`` invocation.

.. warning:: The module must be loaded before any other module that has direct influence on query processing and response generation. The module must be able to intercept an incoming query before the processing of the actual query starts. It must also be able to check the cookies of inbound responses and eventually discard them before they are handled by other functional units.

Properties
----------

.. function:: cookies.config(configuration)

  :param table configuration: part of cookie configuration to be changed, may be called without parameter
  :return: JSON dictionary containing current configuration

  The function may be called without any parameter. In such case it only returns current configuration. The returned JSON also contains available algorithm choices.

Dependencies
------------

* `Nettle <https://www.lysator.liu.se/~nisse/nettle/>`_ required for HMAC-SHA256

