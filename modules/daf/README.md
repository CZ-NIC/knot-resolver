.. _mod-daf:

DNS Application Firewall
------------------------

This module is a high-level interface for other powerful filtering modules and DNS views. It provides an easy interface to apply and monitor DNS filtering rules and a persistent memory for them. It also provides a restful service interface and an HTTP interface.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	modules = { 'http', 'daf' }
