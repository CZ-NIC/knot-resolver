.. _mod-hints:

Static hints
------------

This is a module providing static hints for forward records (A/AAAA) and reverse records (PTR).
The records can be loaded from ``/etc/hosts``-like files and/or added directly.

You can also use the module to change root hints that are used as a safety belt, or if the root NS
drops out of cache.

Examples
^^^^^^^^

.. code-block:: lua

    -- Load hints after iterator
    modules = { 'hints > iterate' }
    -- Load hints before rrcache, custom hosts file
    modules = { ['hints < rrcache'] = 'hosts.custom' }
    -- Add root hints
    hints.root({
      ['j.root-servers.net.'] = { '2001:503:c27::2:30', '192.58.128.30' }
    })
    -- Set custom hint
    hints['localhost'] = '127.0.0.1'

Properties
^^^^^^^^^^

.. function:: hints.config([path])

  :param string path:  path to hosts-like file, default: no file
  :return: ``{ result: bool }``

  Clear any configured hints, and optionally load a hosts-like file as in ``hints.add_hosts(path)``.
  (Root hints are not touched.)

.. function:: hints.add_hosts([path])

  :param string path:  path to hosts-like file, default: `/etc/hosts`

  Add hints from a host-like file.

.. function:: hints.get(hostname)

  :param string hostname: i.e. ``"localhost"``
  :return: ``{ result: [address1, address2, ...] }``

  Return list of address record matching given name.
  If no hostname is specified, all hints are returned in the table format used by ``hints.root()``.

.. function:: hints.set(pair)

  :param string pair:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``
  :return: ``{ result: bool }``

  Add a hostname - address pair hint.

.. function:: hints.del(pair)

  :param string pair:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``, or just ``hostname``
  :return: ``{ result: bool }``

  Remove a hostname - address pair hint.  If address is omitted, all addresses for the given name are deleted.

.. function:: hints.root()

  :return: ``{ ['a.root-servers.net.'] = { '1.2.3.4', '5.6.7.8', ...}, ... }``

  .. tip:: If no parameters are passed, returns current root hints set.

.. function:: hints.root(root_hints)

  :param table root_hints: new set of root hints i.e. ``{['name'] = 'addr', ...}``
  :return: ``{ ['a.root-servers.net.'] = { '1.2.3.4', '5.6.7.8', ...}, ... }``

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

