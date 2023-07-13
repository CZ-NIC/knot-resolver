.. SPDX-License-Identifier: GPL-3.0-or-later

.. _policies-new:

*****************************************
Policy, access control, data manipulation
*****************************************
.. TODO maybe rename the title and the file

.. TODO (whole file) exact description of all currently supported possibilities.
   Where to put such detailed reference?

.. TODO pass again after clearing up what's implemented and what is not.

This chapter briefly describes rules for access control and for overriding DNS by local or remote sources of data.
These rules are declarative, contrary to the imperative Lua commands used before Knot Resolver 6.

Top-level configuration subtrees covered in this chapter are:

- ``forward:`` :ref:`yaml_forward`
  rules overriding which servers get asked to obtain DNS data.
- ``views:`` :ref:`yaml_views`
  as a means to achieve access control, changing answers based on where the DNS request came from.
- ``local-data:`` :ref:`yaml_local-data`
  overriding returned DNS data, which also includes blocking.



.. _yaml_forward:

Forwarding
==========

The ``/forward`` list of rules overrides which servers get asked to obtain DNS data.

.. code-block:: yaml

  forward:
    # ask everything through some public resolver
    - subtree: .
      servers: [ 2001:148f:fffe::1, 193.17.47.1 ]

.. code-block:: yaml

  forward:
    # encrypted public resolver, again for all names
    - subtree: .
      servers:
        - address: [ 2001:148f:fffe::1, 193.17.47.1 ]
          transport: tls
          hostname: odvr.nic.cz

    # use a local authoritative server for an internal-only zone
    - subtree: internal.example.com
      servers: [ 10.0.0.53 ]
      options:
        authoritative: true
        dnssec: false



.. _yaml_views:

Views
=====

Views are a means to achieve access control, changing answers based on where a DNS request came from.

The ``/views`` tree defines a list of rules.  For each request, the resolver chooses the rule with the most specific subnet matching the client's address (at most one rule may be chosen).
Such a rule may tell the resolver to refuse to answer, set some additional options, or choose which groups of content rules would apply (see :ref:`tags`).

.. code-block:: yaml

  views:
    # only allow answering to specific subnets
    - subnets: [ 0.0.0.0/0, "::/0" ] # words starting with :: need quoting.
      answer: refused
    - subnets: [ 10.0.10.0/24, 127.0.0.1, "::1" ]
      answer: allow

.. code-block:: yaml

  views:
    - subnets: [ 2001:db8:1::/56 ]
      tags: [ malware localnames ]
      options:
        dns64: true



.. _yaml_local-data:

Local data
==========

Local overrides for DNS data may be defined in the ``/local-data`` configuration tree.
We support various input formats, described in following subsections.

Records
-------

The typical use case is to define some name-address pairs, which also generate corresponding
`reverse PTR records <https://en.wikipedia.org/wiki/Reverse_DNS_lookup>`_.

.. code-block:: yaml

  local-data:
    addresses:
      a1.example.com: 2001:db8::1
      a2.example.com: 2001:db8::2
    addresses-files:
      - /etc/hosts
    # some options
    ttl: 5m
    nodata: false # don't force empty answer for missing record types on mentioned names

The zonefile syntax is more flexible, e.g. it can define any type of records.

.. code-block:: yaml

  local-data:
    records: |
      www.google.com.  CNAME  forcesafesearch.google.com.
      example.com  TXT  "an example text record"
      34.example.com  AAAA  2001:db8::3
      34.example.com  AAAA  2001:db8::4

RPZ: response policy zones
--------------------------

`RPZ <https://dnsrpz.info>`_
files are another way of adding rules.

.. code-block:: yaml

  local-data:
    rpz:
      - file: /tmp/adult.rpz
        tags: [ adult ]
      - file: /tmp/security.rpz
        # security blocklist applied for everyone

So far, RPZ support is limited to the most common features:

- just files which are *not* automatically reloaded when changed
- rules with ``rpz-*`` labels are ignored, e.g. ``.rpz-client-ip``
- ``CNAME *.some.thing`` does not expand the wildcard

Advanced rules
--------------

The list ``/local-data/subtrees`` allows defining more complex sets of rules.

It allows blocking whole subtrees.

.. future: or use tags on ``addresses`` and ``records` rules


.. code-block:: yaml

  local-data:
    subtrees:
      - type: empty
        tags: [ malware ]
        roots: [ evil.example.org, malware.example.net ]

.. future
      - records: |
          www.google.com.  CNAME  forcesafesearch.google.com.
        tags: [ adult ]

.. _tags:

Tag usage
=========

An incoming request receives a set of tags assigned by :ref:`yaml_views`, which restricts what content rules may apply.
This principle is very similar to
`Unbound's tags <https://unbound.docs.nlnetlabs.nl/en/latest/topics/filtering/tags-views.html>`_
(which were a significant inspiration).

A ``local-data`` rule may only be applied if its tag-set intersects with the tag-set selected for this client -- or if the rule's tag-set is empty.
This matching may be used in quite different ways.  Simple usage pattern examples:

- Rule-focused tags (typical in our examples).  Each content rule has a single tag, so the rules are split into disjunct groups, and for each client we choose an arbitrary subset of these groups.

- Client-focused tags. Each client gets a single tag, so the clients are split into disjunct groups, and for each rule we choose an arbitrary subset of these groups.

- In any case, typically the majority of content rules don't have any tags and thus always apply.

Tag names are basically arbitrary, but the number of tags that you use at once in one resolver instance is limited by a constant (see :c:type:`kr_rule_tags_t`).

Rule precedence
===============

The new rule design is declarative and is aimed at rule combinations that do what most people naturally expect.
Generally, the most specific matching rule is applied in each situation, instead of relying on the order in which the rules are specified.

In particular, narrower subnets win over wider ones and overrides for longer names win over those defined for shorter names (or over subtrees starting closer to the root).  For example, the ``10.in-addr.arpa.`` subtree gets locally answered as empty by default (complying to standards) but if you use ``/local-data/addresses/`` to define some names with addresses inside that range, PTRs for those addresses will be served.  And neither of these rules will be affected by adding a rule with forwarding "everything" to some resolver, so you will still get a local answer or a local denial for all of ``10.in-addr.arpa.``.
