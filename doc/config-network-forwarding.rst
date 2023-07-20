.. SPDX-License-Identifier: GPL-3.0-or-later

Forwarding
----------

*Forwarding* configuration instructs resolver to forward cache-miss queries from clients to manually specified DNS resolvers *(upstream servers)*.
In other words the *forwarding* mode does exact opposite of the default *recursive* mode because resolver in *recursive* mode automatically selects which servers to ask.

Main use-cases are:

  * Building a tree structure of DNS resolvers to improve performance (by improving cache hit rate).
  * Accessing domains which are not available using recursion (e.g. if internal company servers return different answers than public ones).
  * Forwarding through a central DNS traffic filter.

Forwarding implementation in Knot Resolver has following properties:

  * Answers from *upstream* servers are cached.
  * Answers from *upstream* servers are locally DNSSEC-validated, unless dnssec is disabled.
  * Resolver automatically selects which IP address from given set of IP addresses will be used (based on performance characteristics).
  * :ref:`Forwarding <config-forward>` can use either encrypted or unencrypted DNS protocol.

.. warning::

        We strongly discourage use of "fake top-level domains" like ``corp.`` because these made-up domains are indistinguishable from an attack, so DNSSEC validation will prevent such domains from working.
        If you *really* need a variant of forwarding which does not DNSSEC-validate received data please see chapter :ref:`dns-graft`.
        In long-term it is better to migrate data into a legitimate, properly delegated domains which do not suffer from these security problems.


Simple examples for **unencrypted** forwarding:

.. code-block:: yaml

   forward:
     # forward all traffic to specified IP addresses (selected automatically)
     - subtree: "."
       servers: [2001:db8::1, 192.0.2.1]
     # forward only queries for names under domain example.com to a single IP address
     - subtree: example.com.
       servers: [192.0.2.1]

To configure encrypted version please see chapter about :ref:`forwarding <config-forward>`.

Forwarding is documented in depth together with rest of :ref:`config-policy-new`.
