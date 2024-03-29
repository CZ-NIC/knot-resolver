.. SPDX-License-Identifier: GPL-3.0-or-later

Answer reordering
=================

Certain clients are "dumb" and always connect to first IP address or name found
in a DNS answer received from resolver instead of picking randomly.
As a workaround for such broken clients it is possible to randomize
order of records in DNS answers sent by resolver:

.. option:: options/reorder-rrset: true|false

   :default: true

   If set, resolver will vary the order of resource records within RR sets.
   It is enabled by default since 5.3.0.
