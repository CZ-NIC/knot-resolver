.. SPDX-License-Identifier: GPL-3.0-or-later

.. _upgrading:

*********
Upgrading
*********

This section summarizes steps required when upgrading to newer Knot Resolver versions.
We advise users to also read :ref:`release_notes` for respective versions.

5.x to 6.x
==========

See the detailed guide for :ref:`upgrading to version 6.x <upgrading-to-6>`.

Upgrading incompatible configuration changes
============================================

All configuration changes should be listed in :ref:`NEWS <release_notes>`.
This allows you to see the differences between the original version and the new version and adjust the configuration accordingly.
Alternatively, you can use :ref:`kresctl <manager-client>` utility to migrate your old configuration to the new one automatically.
Please backup your configuration just in case.

.. code-block:: bash

   # the migrated configuration will be printed
   # or you can choose the destination file where the new configuration will be saved
   $ kresctl migrate /etc/knot-resolver/config.yaml     # /etc/knot-resolver/config.new.yaml

Older versions
==============

Information for upgrading older versions of the resolver can be found in the older documentation
hosted on `knot-resolver.readthedocs.io/ <https://knot-resolver.readthedocs.io/en/latest/upgrading.html>`_.
