.. SPDX-License-Identifier: GPL-3.0-or-later

Generics library
----------------

This small collection of "generics" was born out of frustration that I couldn't find no
such thing for C. It's either bloated, has poor interface, null-checking is absent or
doesn't allow custom allocation scheme. BSD-licensed (or compatible) code is allowed here,
as long as it comes with a test case in `tests/test_generics.c`.

* array_ - a set of simple macros to make working with dynamic arrays easier.
* queue_ - a FIFO + LIFO queue.
* map_ - a `Crit-bit tree`_ key-value map implementation (public domain) that comes with tests.
* set_ - set abstraction implemented on top of ``map`` (unused now).
* pack_ - length-prefixed list of objects (i.e. array-list).
* lru_ - LRU-like hash table
* trie_ - a trie-based key-value map, taken from knot-dns

array
~~~~~

.. doxygenfile:: array.h
   :project: libkres

queue
~~~~~

.. doxygenfile:: queue.h
   :project: libkres

map
~~~

.. doxygenfile:: map.h
   :project: libkres

set
~~~

.. doxygenfile:: set.h
   :project: libkres

pack
~~~~

.. doxygenfile:: pack.h
   :project: libkres

lru
~~~

.. doxygenfile:: lru.h
   :project: libkres

trie
~~~~

.. doxygenfile:: trie.h
   :project: libkres


.. _`Crit-bit tree`: https://cr.yp.to/critbit.html 
