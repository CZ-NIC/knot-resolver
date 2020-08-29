.. SPDX-License-Identifier: GPL-3.0-or-later

.. _lib_index:

.. include:: ../lib/README.rst

API reference
=============

.. warning:: This section is generated with doxygen and breathe. Due to their
   limitations, some symbols may be incorrectly described or missing entirely.
   For exhaustive and accurate reference, refer to the header files instead.

.. contents::
   :depth: 1
   :local:

.. _lib_api_rplan:

Name resolution
---------------

.. doxygenfile:: resolve.h
   :project: libkres
.. doxygenfile:: rplan.h
   :project: libkres

.. _lib_api_cache:

Cache
-----

.. doxygenfile:: cache/api.h
   :project: libkres

.. _lib_api_nameservers:

Nameservers
-----------

.. doxygenfile:: selection.h
   :project: libkres
.. doxygenfile:: zonecut.h
   :project: libkres

.. _lib_api_modules:

Modules
-------

.. doxygenfile:: module.h
   :project: libkres

.. doxygenfile:: layer.h
   :project: libkres

Utilities
---------

.. doxygenfile:: utils.h
   :project: libkres
.. doxygenfile:: defines.h
   :project: libkres

.. _lib_generics:

.. include:: ../lib/generic/README.rst
