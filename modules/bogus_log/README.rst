.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-bogus_log:

DNSSEC validation failure logging
=================================

This module adds error message for each DNSSEC validation failure.
It is meant to provide hint to operators which queries should be
investigated using diagnostic tools like DNSViz_.

Add following line to your configuration file to enable it:

.. code-block:: lua

        modules.load('bogus_log')

Example of error message logged by this module:

.. code-block:: none

        DNSSEC validation failure dnssec-failed.org. DNSKEY

.. _DNSViz: http://dnsviz.net/

List of most frequent queries which fail as DNSSEC bogus can be obtained at run-time:

.. code-block:: lua

      > bogus_log.frequent()
      [1] => {
          [type] => DNSKEY
          [count] => 1
          [name] => dnssec-failed.org.
      }
      [2] => {
          [type] => DNSKEY
          [count] => 13
          [name] => rhybar.cz.
      }

Please note that in future this module might be replaced
with some other way to log this information.
