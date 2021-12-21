.. SPDX-License-Identifier: GPL-3.0-or-later

Tests
=====

The following is a non-comprehensitve lists of various tests that can be found
in this repo.

Unit tests
----------

The unit tests depend on cmocka_ and can easily be executed after compilation.
They are enabled by default.

.. code-block:: bash

        $ meson test -C build_dir --suite unit

Config tests
------------

Config tests utilize the kresd's lua config file to execute arbitrary tests,
typically testing various modules, their API etc.

These tests require installed kresd. The binary ``kresd`` found in ``$PATH``
will be tested. When testing through meson, ``$PATH`` is modified automatically
and you just need to make sure to install kresd first.

To enable these tests, specify ``-Dconfig_tests=enabled`` option for meson.
Multiple dependencies are required (refer to meson's output when configuring
the build dir).

.. code-block:: bash

        $ meson configure build_dir -Dconfig_tests=enabled
        $ ninja install -C build_dir
        $ meson test -C build_dir --suite config

Integration tests
-----------------

The integration tests are using Deckard, the `DNS test harness <deckard>`_. The
tests simulate specific DNS scenarios, including authoritative server and their
responses.

These tests require installed kresd. The binary ``kresd`` found in ``$PATH``
will be tested. When testing through meson, ``$PATH`` is modified automatically
and you just need to make sure to install kresd first.

To enable these tests, specify ``-Dextra_tests=enabled`` option for meson.
Multiple dependencies are required (refer to meson's output when configuring
the build dir).

Enabling ``extra_tests`` automatically enables config tests as well.

.. code-block:: bash

        $ meson configure build_dir -Dextra_tests=enabled
        $ ninja install -C build_dir
        $ meson test -C build_dir --suite integration

Pytests
-------

The pytest suite is designed to spin up a kresd instance, acquire a connected
socket, and then performs any tests on it. These tests are used to test for
example TCP, TLS and its connection management.

These tests require installed kresd. The binary ``kresd`` found in ``$PATH``
will be tested. When testing through meson, ``$PATH`` is modified automatically
and you just need to make sure to install kresd first.

To enable these tests, specify ``-Dextra_tests=enabled`` option for meson.
Multiple dependencies are required (refer to meson's output when configuring
the build dir).

Enabling ``extra_tests`` automatically enables config tests as well.

.. code-block:: bash

        $ meson configure build_dir -Dextra_tests=enabled
        $ ninja install -C build_dir
        $ meson test -C build_dir --suite pytests


.. _deckard: https://gitlab.nic.cz/knot/deckard
