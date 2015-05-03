.. _mod-hints:

Static hints
------------

This is a module providing static hints from ``/etc/hosts`` like file.

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
