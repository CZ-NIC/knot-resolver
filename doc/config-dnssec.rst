.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-dnssec:

*************************
DNSSEC, data verification
*************************

Good news! Knot Resolver uses secure configuration by default, and this configuration
should not be changed unless absolutely necessary, so feel free to skip over this section.

.. include:: config-dnssec-ta.rst

DNSSEC is main technology to protect data, but it is also possible to change how strictly
resolver checks data from insecure DNS zones:

.. include:: config-dnssec-glue.rst
