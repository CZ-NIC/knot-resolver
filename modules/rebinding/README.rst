.. _mod-rebinding:

Rebinding protection
--------------------

This module provides protection from `DNS Rebinding attack`_ by blocking
answers which cointain IPv4_ or IPv6_ addresses for private use
(or some other special-use addresses).

To enable this module insert following line into your configuration file:

.. code-block:: lua

  modules.load('rebinding < iterate')

Please note that this module does not offer stable configuration interface
yet. For this reason it is suitable mainly for public resolver operators
who do not need to whitelist certain subnets.

.. warning:: Some like to "misuse" such addresses, e.g. `127.*.*.*`
  in blacklists served over DNS, and this module will block such uses.

.. _`DNS Rebinding attack`: https://en.wikipedia.org/wiki/DNS_rebinding
.. _IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
.. _IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
