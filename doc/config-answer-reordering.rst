.. SPDX-License-Identifier: GPL-3.0-or-later

Answer reordering
=================
Certain clients are "dumb" and always connect to first IP address or name found
in a DNS answer received from resolver intead of picking randomly.
As a workaround for such broken clients it is possible to randomize
order of records in DNS answers sent by resolver:

.. function:: reorder_RR([true | false])

   :param boolean new_value: ``true`` to enable or ``false`` to disable randomization *(optional)*
   :return: The (new) value of the option

   If set, resolver will vary the order of resource records within RR sets.
   It is disabled by default.

