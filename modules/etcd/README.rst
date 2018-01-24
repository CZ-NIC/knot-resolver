.. _mod-etcd:

Etcd module
-----------

The module connects to Etcd peers and watches for configuration change.
By default, the module looks for the subtree under ``/knot-resolver`` directory,
but you can change this `in the configuration <https://github.com/mah0x211/lua-etcd#cli-err--etcdnew-optiontable->`_.

The subtree structure corresponds to the configuration variables in the declarative style.

.. code-block:: bash

	$ etcdctl set /knot-resolvevr/net/127.0.0.1 53
	$ etcdctl set /knot-resolver/cache/size 10000000

Configures all listening nodes to following configuration:

.. code-block:: lua

	net = { '127.0.0.1' }
	cache.size = 10000000

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	modules = {
		etcd = {
			prefix = '/knot-resolver',
			peer = 'http://127.0.0.1:7001'
		}
	}

.. warning:: Work in progress!

Dependencies
^^^^^^^^^^^^

* `lua-etcd <https://github.com/mah0x211/lua-etcd>`_ available in LuaRocks

    ``$ luarocks install etcd --from=https://mah0x211.github.io/rocks/``

