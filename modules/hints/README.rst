.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-hints:

Static hints
============

This is a module providing static hints for forward records (A/AAAA) and reverse records (PTR).
The records can be loaded from ``/etc/hosts``-like files and/or added directly.

You can also use the module to change the root hints; they are used as a safety belt or if the root NS
drops out of cache.

.. tip::

   For blocking large lists of domains please use :func:`policy.rpz`
   instead of creating huge list of domains with IP address *0.0.0.0*.

Examples
--------

.. code-block:: lua

    -- Load hints after iterator (so hints take precedence before caches)
    modules = { 'hints > iterate' }
    -- Add a custom hosts file
    hints.add_hosts('hosts.custom')
    -- Override the root hints
    hints.root({
      ['j.root-servers.net.'] = { '2001:503:c27::2:30', '192.58.128.30' }
    })
    -- Add a custom hint
    hints['foo.bar'] = '127.0.0.1'

.. note::
   The :ref:`policy <mod-policy>` module applies before hints,
   so your hints might get surprisingly shadowed by even default policies.

   That most often happens for :rfc:`6761#section-6` names, e.g.
   ``localhost`` and ``test`` or with ``PTR`` records in private address ranges.
   To unblock the required names, you may use an explicit :any:`policy.PASS` action.

   .. code-block:: lua

      policy.add(policy.suffix(policy.PASS, {todname('1.168.192.in-addr.arpa')}))

   This ``.PASS`` workaround isn't ideal.  To improve some cases,
   we recommend to move these ``.PASS`` lines to the end of your rule list.
   The point is that applying any :ref:`non-chain action <mod-policy-actions>`
   (e.g. :ref:`forwarding actions <forwarding>` or ``.PASS`` itself)
   stops processing *any* later policy rules for that request (including the default block-rules).
   You probably don't want this ``.PASS`` to shadow any other rules you might have;
   and on the other hand, if any other non-chain rule triggers,
   additional ``.PASS`` would not change anything even if it were somehow force-executed.

Properties
----------

.. function:: hints.config([path])

  :param string path:  path to hosts-like file, default: no file
  :return: ``{ result: bool }``

  Clear any configured hints, and optionally load a hosts-like file as in ``hints.add_hosts(path)``.
  (Root hints are not touched.)

.. function:: hints.add_hosts([path])

  :param string path:  path to hosts-like file, default: ``/etc/hosts``

  Add hints from a host-like file.

.. function:: hints.get(hostname)

  :param string hostname: i.e. ``"localhost"``
  :return: ``{ result: [address1, address2, ...] }``

  Return list of address record matching given name.
  If no hostname is specified, all hints are returned in the table format used by ``hints.root()``.

.. function:: hints.set(pair)

  :param string pair:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``
  :return: ``{ result: bool }``

  Add a hostname--address pair hint.

  .. note::

    If multiple addresses have been added for a name (in separate ``hints.set()`` commands),
    all are returned in a forward query.
    If multiple names have been added to an address, the last one defined is returned
    in a corresponding PTR query.

.. function:: hints.del(pair)

  :param string pair:  ``hostname address`` i.e. ``"localhost 127.0.0.1"``, or just ``hostname``
  :return: ``{ result: bool }``

  Remove a hostname - address pair hint.  If address is omitted, all addresses for the given name are deleted.

.. function:: hints.root_file(path)

  Replace current root hints from a zonefile.  If the path is omitted, the compiled-in path is used, i.e. the root hints are reset to the default.

.. function:: hints.root(root_hints)

  :param table root_hints: new set of root hints i.e. ``{['name'] = 'addr', ...}``
  :return: ``{ ['a.root-servers.net.'] = { '1.2.3.4', '5.6.7.8', ...}, ... }``

  Replace current root hints and return the current table of root hints.

  .. tip:: If no parameters are passed, it only returns current root hints set without changing anything.

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

.. function:: hints.use_nodata(toggle)

  :param bool toggle: true if enabling NODATA synthesis, false if disabling
  :return: ``{ result: bool }``

  If set to true (the default), NODATA will be synthesised for matching hint name, but mismatching type (e.g. AAAA query when only A hint exists).

.. function:: hints.ttl([new_ttl])

  :param int new_ttl: new TTL to set (optional)
  :return: the TTL setting

  This function allows to read and write the TTL value used for records generated by the hints module.

