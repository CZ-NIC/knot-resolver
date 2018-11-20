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
   $ pytest-3 -s # turn on verbose logs even for successfull tests

It's highly recommended to run these tests in parallel, since lot of them
wait for kresd timeout. This can be don with `python-xdist`:

.. code-block:: bash

   $ pytest-3 -n 24  # parallel with 24 jobs

Each test spawns an independent kresd instance, so test failures shouldn't affect
each other. However, when using lots of parallel jobs, it is possible an already taken
port will be assigned to kresd. These cases will be detected and result in skipped
tests.

Some tests are ommitted from automatic test collection by default, due to their
resource contraints. These typicially have to be executed separately by providing
the path to test file directly.

.. code-block:: bash

   $ pytest-3 conn_flood.py

Developer notes
---------------

Typically, each test requires a setup of kresd, and a connected socket to run tests on.
The framework provides a few useful pytest fixtures to simplify this process:

- `kresd_sock` provides a connected socket to a test-specific, running kresd instance.
  It expands to 4 values (tests) - IPv4 TCP, IPv6 TCP, IPv4 TLS, IPv6 TLS sockets
- `make_kresd_sock` is similar to `kresd_sock`, except it's a factory function that
  produces a new connected socket (of the same type) on each call
- `kresd`, `kresd_tt`, `kresd_tt_expired` are all Kresd instances, already running
  and initialized with config (with no / valid / expired TLS certificates)
