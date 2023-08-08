.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-policy-new:

*****************************************
Policy, access control, data manipulation
*****************************************

This chapter briefly describes rules for access control and for overriding DNS by local or remote sources of data.
These rules are declarative, contrary to the imperative Lua commands used before Knot Resolver 6.

The main parts described in this chapter are:

* :ref:`views: <config-views>` A means of achieving access control by changing responses based on where the DNS request came from.
* :ref:`local-data: <config-local-data>` Overriding returned DNS data, which also includes blocking.
* :ref:`forward: <config-forward>` Rules overriding which servers get asked to obtain DNS data.

The so-called :ref:`tags <config-policy-new-tags>` are used to link clients defined using :ref:`views <config-views>` and the rules applied to them in :ref:`local-data <config-local-data>`.

It is also possible to modify data returned to clients, either by providing
:ref:`config-dns64` translation, or :ref:`config-renumber`.

Additional features offer protection against various DNS-based attacks,
see :ref:`config-rebinding` and :ref:`config-refuse-no-rd`.

.. toctree::
   :maxdepth: 1

   config-views
   config-local-data
   config-forward
   config-dns64
   config-renumber
   config-reordering
   config-rebinding
   config-refuse-no-rd

.. _config-policy-new-tags:

Tags
====

An incoming request receives a set of tags assigned by :ref:`views <config-views>`, which restricts what content rules may apply.
This principle is very similar to
`Unbound's tags <https://unbound.docs.nlnetlabs.nl/en/latest/topics/filtering/tags-views.html>`_
(which were a significant inspiration).

A :ref:`local-data <config-local-data>` rule may only be applied if its tag-set intersects with the tag-set selected for this client -- or if the rule's tag-set is empty.
This matching may be used in quite different ways.  Simple usage pattern examples:

*  Rule-focused tags (typical in our examples).  Each content rule has a single tag, so the rules are split into disjunct groups, and for each client we choose an arbitrary subset of these groups.
* Client-focused tags. Each client gets a single tag, so the clients are split into disjunct groups, and for each rule we choose an arbitrary subset of these groups.
* In any case, typically the majority of content rules don't have any tags and thus always apply.

Tag names are basically arbitrary, but the number of tags that you use at once in one resolver instance is limited by a constant (see :c:type:`kr_rule_tags_t`).
