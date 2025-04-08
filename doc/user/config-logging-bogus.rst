.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-logging-bogus:

DNSSEC validation failure logging
=================================

This logs a message for each DNSSEC validation failure (on ``notice`` logging level).
It is meant to provide hint to operators which queries should be
investigated using diagnostic tools like DNSViz_.

Add following line to your configuration file to enable it:

.. code-block:: yaml

   dnssec:
      log-bogus: true

Example of error message logged:

.. code-block:: none

        [dnssec] validation failure: dnssec-failed.org. DNSKEY

.. _DNSViz: http://dnsviz.net/

.. List of most frequent queries which fail as DNSSEC bogus can be obtained at run-time:

.. .. code-block:: lua

..       > bogus_log.frequent()
..       {
..           {
..               ['count'] = 1,
..               ['name'] = 'dnssec-failed.org.',
..               ['type'] = 'DNSKEY',
..           },
..           {
..               ['count'] = 13,
..               ['name'] = 'rhybar.cz.',
..               ['type'] = 'DNSKEY',
..           },
..       }

.. Please note that in future this might be replaced
.. with some other way to log this information.
