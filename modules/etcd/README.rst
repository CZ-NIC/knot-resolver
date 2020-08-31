.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-etcd:

Etcd support
------------

The `etcd` module connects to `etcd <https://etcd.io/>`_ peers and watches
for configuration changes. By default, the module watches the subtree under
``/knot-resolver`` directory, but you can change this in the
`etcd library configuration <https://github.com/mah0x211/lua-etcd#cli-err--etcdnew-optiontable->`_.

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

	modules.load('etcd')
        etcd.config({
                prefix = '/knot-resolver',
                peer = 'http://127.0.0.1:7001'
        })

.. warning:: Work in progress!

Dependencies
^^^^^^^^^^^^

* `lua-etcd <https://github.com/mah0x211/lua-etcd>`_ library available in LuaRocks

    ``$ luarocks --lua-version 5.1 install etcd --from=https://mah0x211.github.io/rocks/``

