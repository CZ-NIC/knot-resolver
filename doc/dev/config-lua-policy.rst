.. SPDX-License-Identifier: GPL-3.0-or-later

.. _policies:

*****************************************
Policy, access control, data manipulation
*****************************************

Features in this section allow to configure what clients can get access to what
DNS data, i.e. DNS data filtering and manipulation.

:ref:`mod-policy` specify global policies applicable to all requests,
e.g. for blocking access to particular domain. :ref:`mod-view` allow
to specify per-client policies, e.g. block or unblock access
to a domain only for subset of clients.

It is also possible to modify data returned to clients, either by providing
:ref:`mod-hints` (answers with statically configured IP addresses),
:ref:`mod-dns64` translation, or :ref:`mod-renumber`.

Additional modules offer protection against various DNS-based attacks,
see :ref:`mod-rebinding` and :ref:`mod-refuse_nord`.

At the very end, module :ref:`mod-daf` provides HTTP API for run-time policy
modification, and generally just offers different interface for previously
mentioned features.


.. toctree::
   :maxdepth: 1

   modules-policy
   modules-view
   modules-hints
   modules-dns64
   modules-renumber
   config-answer-reordering
   modules-rebinding
   modules-refuse_nord
   modules-daf

