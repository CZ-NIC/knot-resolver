.. SPDX-License-Identifier: GPL-3.0-or-later

Python client tests for kresd
=============================

The tests run `/usr/bin/env kresd` (can be modified with `$PATH`) with custom config
and execute client-side testing, such as TCP / TLS connection management.

Requirements
------------

- pip3 install -r requirements.txt

Executing tests
---------------

Tests can be executed with the pytest framework.

.. code-block:: bash

   $ pytest-3  # sequential, all tests (with exception of few special tests)
   $ pytest-3 test_conn_mgmt.py::test_ignore_garbage   # specific test only
   $ pytest-3 --html pytests.html --self-contained-html  # html report

It's highly recommended to run these tests in parallel, since lot of them
wait for kresd timeout. This can be done with `python-xdist`:

.. code-block:: bash

   $ pytest-3 -n 24  # parallel with 24 jobs

Each test spawns an independent kresd instance, so test failures shouldn't affect
each other.

Some tests are omitted from automatic test collection by default, due to their
resource constraints. These typicially have to be executed separately by providing
the path to test file directly.

.. code-block:: bash

   $ pytest-3 conn_flood.py

Note: some tests may fail without an internet connection.

Developer notes
---------------

Typically, each test requires a setup of kresd, and a connected socket to run tests on.
The framework provides a few useful pytest fixtures to simplify this process:

- `kresd_sock` provides a connected socket to a test-specific, running kresd instance.
  It expands to 4 values (tests) - IPv4 TCP, IPv6 TCP, IPv4 TLS, IPv6 TLS sockets
- `make_kresd_sock` is similar to `kresd_sock`, except it's a factory function that
  produces a new connected socket (of the same type) on each call
- `kresd`, `kresd_tt` are all Kresd instances, already running
  and initialized with config (with no / valid TLS certificates)
