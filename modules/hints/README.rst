.. _mod-hints:

Static hints
------------

This is a module providing static hints from ``/etc/hosts`` like file.
You can also use it to change root hints that are used as a safety belt or if the root NS
drops out of cache.

Properties
^^^^^^^^^^

.. function:: hints.config([path])

  :param string path:  path to hosts file, default: ``"/etc/hosts"``
  :return: ``{ result: bool }``
  
  Load specified hosts file.

.. function:: hints.get(hostname)

  :param string hostname: i.e. ``"localhost"``
  :return: ``{ result: [address1, address2, ...] }``

  Return list of address record matching given name.

.. function:: hints.set(pair)

  :param string pair:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``
  :return: ``{ result: bool }``

  Set hostname - address pair hint.

.. function:: hints.root()

  :return: ``{ ['a.root-servers.net'] = { '1.2.3.4', '5.6.7.8', ...}, ... }``

  .. tip:: If no parameters are passed, returns current root hints set.

.. function:: hints.root(root_hints)

  :param table root_hints: new set of root hints i.e. ``{['name'] = 'addr', ...}``
  :return: ``{ ['a.root-servers.net'] = { '1.2.3.4', '5.6.7.8', ...}, ... }``

  Replace current root hints and return the current table of root hints.

  Example:

  .. code-block:: lua

	> hints.root({
		['l.root-servers.net.'] = '199.7.83.42',
		['m.root-servers.net.'] = '202.12.27.33'
	})
	[l.root-servers.net.] => {
	    [1] => 199.7.83.42
	}
	[m.root-servers.net.] => {
	    [1] => 202.12.27.33
	}

  .. tip:: A good rule of thumb is to select only a few fastest root hints. The server learns RTT and NS quality over time, and thus tries all servers available. You can help it by preselecting the candidates.
  