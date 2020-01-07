.. _dnssec-config:

*************************
DNSSEC, data verification
*************************

Since version 4.0, **DNSSEC validation is enabled by default**.
This is secure default and should not be changed unless absolutely necessary.

.. include:: ../daemon/lua/trust_anchors.rst

TODO: Some heading?
===================

DNSSEC is main technology to protect data, but it is also possible to change how strictly
resolver checks data from insecure DNS zones:

.. include:: ../lib/layer/mode.rst
