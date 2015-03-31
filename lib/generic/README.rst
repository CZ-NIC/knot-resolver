Generics library
----------------

This small collection of "generics" was born out of frustration that I couldn't find no
such thing for C. It's either bloated, has poor interface, null-checking is absent or
doesn't allow custom allocation scheme. BSD-licensed (or compatible) code is allowed here,
as long as it comes with a test case in `tests/test_generics.c`.

Data structures
~~~~~~~~~~~~~~~

* ``array`` - a set of simple macros to make working with dynamic arrays easier.
* ``set`` - a `Crit-bit tree`_ simple implementation (public domain) that comes with tests.
* ``map`` - key-value map implemented on top of ``set``.

API reference and examples
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygengroup:: generics
   :project: libkresolve

.. _`Crit-bit tree`: http://cr.yp.to/critbit.html 