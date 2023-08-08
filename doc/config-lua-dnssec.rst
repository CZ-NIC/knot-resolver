.. SPDX-License-Identifier: GPL-3.0-or-later

.. _dnssec-config:

*************************
DNSSEC, data verification
*************************

Good news! Knot Resolver uses secure configuration by default, and this configuration
should not be changed unless absolutely necessary, so feel free to skip over this section.

.. include:: ../daemon/lua/trust_anchors.rst

DNSSEC is main technology to protect data, but it is also possible to change how strictly
resolver checks data from insecure DNS zones:

.. include:: ../lib/layer/mode.rst
