.. _mod-version:

Version
-------

Module checks for new version and CVE_, and issues warning messages.

Configuration
^^^^^^^^^^^^^
.. code-block:: lua

	   version.config(2*day)
       -- configure period of check (defaults to 1*day)

Running
^^^^^^^

.. code-block:: lua

	   modules.load("version")

.. _cve: https://cve.mitre.org/
